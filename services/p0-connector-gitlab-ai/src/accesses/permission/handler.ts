import {
  type AnyConnectorTRPCInstance,
  type ConnectorContext,
  ConnectorError,
  type Logger,
  type ResourceRootSchemaOf,
  newResourceRootRouter,
  throwAssertNever,
} from "@p0security/connector";
import {
  type SecretManagerProviderConfig,
  SecretNotFoundError,
  type SecretRef,
  createSecretManagerClient,
} from "@p0security/secret-manager-client";
import { createHash } from "node:crypto";

import {
  type GitlabAuth,
  createServiceAccount,
  createServiceAccountToken,
  deleteServiceAccount,
  findServiceAccountId,
  findServiceAccountTokenId,
  getProject,
  listGroupProjects,
  listMemberProjects,
  removeProjectMember,
  revokeServiceAccountToken,
  setProjectMember,
} from "../../gitlab/gitlab-api.ts";
import { getAdminToken } from "../../secrets.ts";
import { GitlabRoleAccessLevels, spec } from "./definition.ts";

type ResourceSchema = ResourceRootSchemaOf<typeof spec>;
type RequestContext = ResourceSchema["RequestContext"];
type GroupContext = ResourceSchema["ListerQuery"]["context"];

// The GitLab MCP server accepts only tokens with the `mcp` scope.
const GRANT_TOKEN_SCOPES = ["mcp"];

const secretRef = (secretArn: string) => secretArn as SecretRef;

const secretManagerConfig = (
  secrets: GroupContext["secrets"]
): SecretManagerProviderConfig => {
  switch (secrets.manager) {
    case "aws":
      return { provider: "aws", region: secrets.region };
    case "gcp":
      return { provider: "gcp", projectId: secrets.projectId };
    default:
      throw throwAssertNever(secrets);
  }
};

const createSecretManager = async (context: GroupContext) => {
  try {
    return await createSecretManagerClient(
      secretManagerConfig(context.secrets)
    );
  } catch {
    throw new ConnectorError({
      type: "validation_error",
      message: "Invalid secret manager",
      payload: { manager: context.secrets.manager },
    });
  }
};

/** The secret manager, plus the admin token that manages grant service
 * accounts. */
const newGroupClients = async (context: GroupContext) => {
  const secretManager = await createSecretManager(context);
  const token = await getAdminToken(
    secretManager,
    secretRef(context.secrets.adminTokenSecretId)
  );
  const auth: GitlabAuth = { token };
  return { secretManager, auth };
};

/** The username of the grant's service account. Usernames are global on
 * GitLab.com, and the secret ref is unique to one customer's grant. */
const usernameFor = (userId: ResourceSchema["UserId"]) =>
  `p0-grant-${createHash("sha256").update(userId).digest("hex").slice(0, 32)}`;

/** The name of the grant's token. The secret holds only the token, so the
 * connector finds the token's id by this name. */
const tokenNameFor = (userId: ResourceSchema["UserId"]) => `P0 ${userId}`;

const tomorrow = () =>
  new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString().slice(0, 10);

/** The projects that a service account is a member of. Only an administrator
 * can list another user's memberships, so this uses a short-lived token of
 * the service account itself. */
const memberProjectsOf = async (
  auth: GitlabAuth,
  groupId: string,
  userId: number
) => {
  const probe = await createServiceAccountToken(auth, {
    groupId,
    userId,
    name: "P0 membership check",
    scopes: ["read_api"],
    expiresAt: tomorrow(),
  });
  try {
    return await listMemberProjects({ token: probe.token });
  } finally {
    await revokeServiceAccountToken(auth, {
      groupId,
      userId,
      tokenId: probe.id,
    });
  }
};

/** Makes the service account a member of exactly the policy's projects, each
 * with its role. */
const syncMemberships = async (
  log: Logger,
  auth: GitlabAuth,
  params: {
    groupId: string;
    userId: number;
    isNew: boolean;
    memberships: ResourceSchema["Policy"]["memberships"];
  }
) => {
  const { groupId, userId, isNew, memberships } = params;
  const desired = await Promise.all(
    memberships.map(async ({ project, role }) => ({
      project: await getProject(auth, project),
      accessLevel: GitlabRoleAccessLevels[role],
    }))
  );
  const current = isNew ? [] : await memberProjectsOf(auth, groupId, userId);

  for (const { project, accessLevel } of desired) {
    await setProjectMember(auth, {
      projectId: project.id,
      userId,
      accessLevel,
    });
  }
  const desiredIds = new Set(desired.map(({ project }) => project.id));
  const stale = current.filter((project) => !desiredIds.has(project.id));
  for (const project of stale) {
    await removeProjectMember(auth, { projectId: project.id, userId });
  }
  log.info(
    { nProjects: desired.length, nRemoved: stale.length },
    "set service account project memberships"
  );
};

/**
 * Gives the grant's service account exactly the policy's project memberships.
 * The first call creates the service account and its token, and writes the
 * token to the secret; later calls change only the memberships. No
 * memberships deletes the service account, which also revokes its token.
 */
const setGrantMemberships = async (
  log: Logger,
  context: RequestContext,
  userId: ResourceSchema["UserId"],
  policies: ResourceSchema["Policy"][]
) => {
  if (policies.length !== 1) {
    log.error(
      { nPolicies: policies.length },
      "expected exactly 1 policy for GitLab memberships"
    );
    // "unknown" rather than "validation_error": this is a control-plane bug,
    // not a problem with the user's request.
    throw new ConnectorError({
      type: "unknown",
      message:
        "Invalid parameters for GitLab memberships, expected exactly 1 policy",
      payload: { requestId: context.requestId, nPolicies: policies.length },
    });
  }

  const [{ memberships }] = policies;
  const { groupId } = context;
  const { secretManager, auth } = await newGroupClients(context);
  const username = usernameFor(userId);
  const existingId = await findServiceAccountId(auth, { groupId, username });

  if (memberships.length === 0) {
    if (existingId !== undefined) {
      await deleteServiceAccount(auth, { groupId, userId: existingId });
      log.info(
        { serviceAccountId: existingId },
        "deleted service account; no memberships remain"
      );
    }
    return;
  }

  const serviceAccountId =
    existingId ??
    (await createServiceAccount(auth, {
      groupId,
      username,
      name: "P0 grant",
    }));
  if (existingId === undefined) {
    log.info({ serviceAccountId }, "created service account");
  }

  // The GitLab MCP server decides whether a user may connect on the user's
  // first call, and keeps that answer. So the memberships must exist before
  // the token does.
  await syncMemberships(log, auth, {
    groupId,
    userId: serviceAccountId,
    isNew: existingId === undefined,
    memberships,
  });

  const name = tokenNameFor(userId);
  // The connector cannot read a grant secret back, so an existing token is
  // trusted to be the secret's value.
  const tokenId = await findServiceAccountTokenId(auth, {
    groupId,
    userId: serviceAccountId,
    name,
  });
  if (tokenId !== undefined) return;

  const token = await createServiceAccountToken(auth, {
    groupId,
    userId: serviceAccountId,
    name,
    scopes: GRANT_TOKEN_SCOPES,
  });
  try {
    await secretManager.createSecretVersion({
      ref: secretRef(userId),
      type: "value",
      value: Buffer.from(token.token),
    });
  } catch (error) {
    // Revoke the token that this call made, so that a failed grant does not
    // leave a valid token that no secret holds.
    await revokeServiceAccountToken(auth, {
      groupId,
      userId: serviceAccountId,
      tokenId: token.id,
    }).catch((revokeError: unknown) =>
      log.error(
        { tokenId: token.id, error: revokeError },
        "failed to revoke the token of a failed grant; it stays valid until revoked"
      )
    );
    throw error;
  }
  log.info(
    { serviceAccountId, tokenId: token.id },
    "created token and stored it in the secret"
  );
};

/**
 * GitLab grant lifecycle
 *
 * The abstract "user" of the resource-root paradigm is the grant's secret. It
 * holds one token of a service account that exists only for this grant. Its
 * policy is the service account's project memberships.
 *
 * Deleting the service account is what removes access, so every delete
 * failure propagates.
 *
 * The P0 control plane must serialize calls for the same secret.
 */
export const router = (t: AnyConnectorTRPCInstance) =>
  newResourceRootRouter<ResourceSchema>(t, spec, (ctx: ConnectorContext) => ({
    // TODO: add validation later.
    validation: () => ({ user: null }),

    getUser: async (context, username) => {
      const logger = ctx.logger.child({
        username,
        requestId: context.requestId,
      });
      const secretManager = await createSecretManager(context);
      try {
        const { ref } = await secretManager.getSecret({
          ref: secretRef(username),
        });
        // Return the ref, as createUser does: the token and service account
        // names come from it, so both must give the same user id.
        return ref;
      } catch (error) {
        // A missing secret means the user does not exist yet; return null so
        // the framework provisions one.
        if (error instanceof SecretNotFoundError) {
          logger.debug("no existing secret found; user will be provisioned");
          return null;
        }
        logger.error({ error }, "failed to look up secret");
        throw error;
      }
    },

    createUser: async (context, username) => {
      const logger = ctx.logger.child({
        username,
        requestId: context.requestId,
      });
      const secretManager = await createSecretManager(context);
      const secret = await secretManager.createSecret({ name: username });
      logger.info({ secretRef: secret.ref }, "created new secret");
      return secret.ref;
    },

    deleteUser: async (context, userId) => {
      const logger = ctx.logger.child({ userId, requestId: context.requestId });
      const { secretManager, auth } = await newGroupClients(context);
      const serviceAccountId = await findServiceAccountId(auth, {
        groupId: context.groupId,
        username: usernameFor(userId),
      });
      // Delete the service account before the secret, so that a failed
      // delete leaves the secret for the retry.
      if (serviceAccountId !== undefined) {
        await deleteServiceAccount(auth, {
          groupId: context.groupId,
          userId: serviceAccountId,
        });
        logger.info({ serviceAccountId }, "deleted service account");
      }
      await secretManager.deleteSecret({ ref: secretRef(userId) });
      logger.info("deleted secret");
    },

    setPoliciesForUser: async (context, userId, _user, policies) => {
      const logger = ctx.logger.child({ userId, requestId: context.requestId });
      await setGrantMemberships(logger, context, userId, policies);
    },

    list: async ({ type, context }) => {
      const logger = ctx.logger.child({ groupId: context.groupId });
      switch (type) {
        case "policy": {
          const { auth } = await newGroupClients(context);
          const projects = await listGroupProjects(auth, context.groupId);
          logger.info({ count: projects.length }, "listed group projects");
          return projects.flatMap(({ pathWithNamespace }) =>
            Object.keys(GitlabRoleAccessLevels).map((role) => ({
              key: `${pathWithNamespace}:${role}`,
              value: `${pathWithNamespace}:${role}`,
              group: pathWithNamespace,
            }))
          );
        }
        default:
          throw throwAssertNever(type);
      }
    },
  }));
