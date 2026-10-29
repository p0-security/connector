import {
  type AnyConnectorTRPCInstance,
  type ConnectorContext,
  ConnectorError,
  type Logger,
  type ResourceRootSchemaOf,
  newResourceRootRouter,
  throwAssertNever,
} from "@p0security/connector-core";
import {
  type SecretManagerProviderConfig,
  SecretNotFoundError,
  type SecretRef,
  createSecretManagerClient,
} from "@p0security/connector-secret-manager-client";
import { createHash } from "node:crypto";

import { getAdminApp } from "../../secrets.ts";
import {
  type Capability,
  type PermissionTarget,
  type SiteRole,
  type TableauSession,
  addUserCapabilities,
  createUser,
  findUser,
  getUserCapabilities,
  listLockedProjects,
  removeUser,
  removeUserCapability,
  setSiteRole,
  signIn,
  signOut,
} from "../../tableau/tableau-api.ts";
import { PROJECT_GRANT_PATTERN, spec } from "./definition.ts";

type ResourceSchema = ResourceRootSchemaOf<typeof spec>;
type RequestContext = ResourceSchema["RequestContext"];
type SiteContext = ResourceSchema["ListerQuery"]["context"];

type Level = "read" | "write";

const ADMIN_SCOPES = [
  "tableau:content:read",
  "tableau:users:*",
  "tableau:permissions:read",
  "tableau:permissions:update",
  "tableau:permissions:delete",
];

// The agent's session keeps these scopes; the agent user's permissions decide
// which content they reach.
const READ_SCOPES = [
  "tableau:content:read",
  // tableau-mcp reads the site's MCP settings before it lists its tools.
  "tableau:mcp_site_settings:read",
  "tableau:viz_data_service:read",
  "tableau:views:download",
];

const AGENT_SCOPES: Record<Level, string[]> = {
  read: READ_SCOPES,
  write: [...READ_SCOPES, "tableau:workbooks:*", "tableau:datasources:*"],
};

const SITE_ROLES: Record<Level, SiteRole> = {
  read: "Viewer",
  write: "ExplorerCanPublish",
};

const allow = (names: string[]): Capability[] =>
  names.map((name) => ({ name, mode: "Allow" }));

const READ_WORKBOOK = [
  "Read",
  "Filter",
  "ViewComments",
  "AddComment",
  "ExportImage",
  "ExportData",
];

const CAPABILITIES: Record<Level, Record<PermissionTarget, Capability[]>> = {
  read: {
    project: allow(["Read"]),
    workbooks: allow(READ_WORKBOOK),
    datasources: allow(["Read", "Connect"]),
  },
  write: {
    project: allow(["Read", "Write"]),
    workbooks: allow([
      ...READ_WORKBOOK,
      "ShareView",
      "ViewUnderlyingData",
      "ExportXml",
      "WebAuthoring",
      "Write",
    ]),
    datasources: allow(["Read", "Connect", "ExportXml", "Write"]),
  },
};

const TARGETS: PermissionTarget[] = ["project", "workbooks", "datasources"];

const secretRef = (secretArn: string) => secretArn as SecretRef;

const secretManagerConfig = (
  secrets: SiteContext["secrets"]
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

const createSecretManager = async (context: SiteContext) => {
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

const siteOf = ({ server, contentUrl }: SiteContext) => ({
  server,
  contentUrl,
});

/** The secret manager, the admin connected app, and an admin session. Sign the
 * session out when done. */
const newSiteClients = async (context: SiteContext) => {
  const secretManager = await createSecretManager(context);
  const app = await getAdminApp(
    secretManager,
    secretRef(context.secrets.adminAppSecretId)
  );
  const admin = await signIn(
    siteOf(context),
    app,
    context.adminUser,
    ADMIN_SCOPES
  );
  return { secretManager, app, admin };
};

/** The grant's agent user: the agent mailbox, plus-addressed with a hash of
 * the grant's secret. Tableau Cloud user names are email addresses. */
const agentUserNameFor = (
  agentMailbox: string,
  userId: ResourceSchema["UserId"]
) => {
  const [local, domain] = agentMailbox.split("@");
  const suffix = createHash("sha256").update(userId).digest("hex").slice(0, 16);
  return `${local}+p0-${suffix}@${domain}`;
};

/** Each project's highest requested level. */
const toProjectLevels = (grants: string[]) => {
  const levels = new Map<string, Level>();
  for (const grant of grants) {
    const [, level, projectId] = PROJECT_GRANT_PATTERN.exec(grant) ?? [];
    if (levels.get(projectId) !== "write")
      levels.set(projectId, level as Level);
  }
  return levels;
};

/** The level a project gives the user now, from its own permissions. */
const currentLevel = (projectCapabilities: Capability[]): Level | undefined => {
  if (projectCapabilities.length === 0) return undefined;
  return projectCapabilities.some(({ name }) => name === "Write")
    ? "write"
    : "read";
};

const removeProjectAccess = async (
  admin: TableauSession,
  projectId: string,
  userId: string
) => {
  for (const target of TARGETS) {
    const capabilities = await getUserCapabilities(
      admin,
      projectId,
      target,
      userId
    );
    for (const capability of capabilities) {
      await removeUserCapability(admin, projectId, target, userId, capability);
    }
  }
};

const addProjectAccess = async (
  admin: TableauSession,
  projectId: string,
  userId: string,
  level: Level
) => {
  for (const target of TARGETS) {
    await addUserCapabilities(
      admin,
      projectId,
      target,
      userId,
      CAPABILITIES[level][target]
    );
  }
};

/**
 * Gives the grant's agent user exactly the requested project access, then
 * writes a new session token for it to the grant's secret. An empty set of
 * grants removes the agent user, which ends its open sessions.
 */
const setGrantAccess = async (
  log: Logger,
  context: RequestContext,
  userId: ResourceSchema["UserId"],
  policies: ResourceSchema["Policy"][]
) => {
  if (policies.length !== 1) {
    log.error(
      { nPolicies: policies.length },
      "expected exactly 1 policy for Tableau project grants"
    );
    // "unknown" rather than "validation_error": this is a control-plane bug,
    // not a problem with the user's request.
    throw new ConnectorError({
      type: "unknown",
      message:
        "Invalid parameters for Tableau project grants, expected exactly 1 policy",
      payload: { requestId: context.requestId, nPolicies: policies.length },
    });
  }

  const [{ grants }] = policies;
  const levels = toProjectLevels(grants);
  const agentName = agentUserNameFor(context.agentMailbox, userId);
  const { secretManager, app, admin } = await newSiteClients(context);
  try {
    const existing = await findUser(admin, agentName);

    if (levels.size === 0) {
      if (existing) {
        await removeUser(admin, existing.id);
        log.info(
          { agentUserId: existing.id },
          "removed agent user; no grants remain"
        );
      }
      return;
    }

    const maxLevel: Level = [...levels.values()].includes("write")
      ? "write"
      : "read";
    const siteRole = SITE_ROLES[maxLevel];
    const agent = existing ?? (await createUser(admin, agentName, siteRole));
    if (!existing) log.info({ agentUserId: agent.id }, "created agent user");
    else if (existing.siteRole !== siteRole) {
      await setSiteRole(admin, agent.id, siteRole);
      log.info({ agentUserId: agent.id, siteRole }, "changed agent site role");
    }

    // Only locked projects apply their default permissions to all content.
    const projects = await listLockedProjects(admin);
    const lockedIds = new Set(projects.map(({ id }) => id));
    const unknown = [...levels.keys()].filter((id) => !lockedIds.has(id));
    if (unknown.length > 0) {
      throw new ConnectorError({
        type: "validation_error",
        message:
          "Tableau projects must exist and have permissions locked to the project",
        payload: { projectIds: unknown.join(",") },
      });
    }

    for (const { id } of projects) {
      const want = levels.get(id);
      const have = currentLevel(
        await getUserCapabilities(admin, id, "project", agent.id)
      );
      if (want === have) continue;
      if (have) await removeProjectAccess(admin, id, agent.id);
      if (want) await addProjectAccess(admin, id, agent.id, want);
      log.info(
        { projectId: id, from: have, to: want },
        "changed project access"
      );
    }

    const session = await signIn(
      admin.site,
      app,
      agentName,
      AGENT_SCOPES[maxLevel]
    );
    await secretManager.createSecretVersion({
      ref: secretRef(userId),
      type: "value",
      value: Buffer.from(session.token),
    });
    log.info(
      { agentUserId: agent.id, nProjects: levels.size },
      "stored a new agent session token in the secret"
    );
  } finally {
    await signOut(admin);
  }
};

/**
 * Tableau agent user lifecycle
 *
 * The abstract "user" of the resource-root paradigm is the grant's secret. It
 * holds a session token for an agent user that P0 creates in the site. Its
 * policies are project grants: the agent user gets read or write permissions
 * on each project, and its content through the project's locked default
 * permissions.
 *
 * Removing the agent user ends its sessions. A revoke is the only thing that
 * removes access, so every revoke failure propagates.
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
        // Return the ref, as createUser does: the agent user's name is derived
        // from it, so both must give the same user id.
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
      const { secretManager, admin } = await newSiteClients(context);
      try {
        const agent = await findUser(
          admin,
          agentUserNameFor(context.agentMailbox, userId)
        );
        // Remove the agent user before deleting the secret, so that a failed
        // removal leaves the secret for the retry.
        if (agent) {
          await removeUser(admin, agent.id);
          logger.info({ agentUserId: agent.id }, "removed agent user");
        }
      } finally {
        await signOut(admin);
      }
      await secretManager.deleteSecret({ ref: secretRef(userId) });
      logger.info("deleted secret");
    },

    setPoliciesForUser: async (context, userId, _user, policies) => {
      const logger = ctx.logger.child({ userId, requestId: context.requestId });
      await setGrantAccess(logger, context, userId, policies);
    },

    list: async ({ type, context }) => {
      const logger = ctx.logger.child({ site: context.contentUrl });
      switch (type) {
        case "project": {
          const { admin } = await newSiteClients(context);
          try {
            const projects = await listLockedProjects(admin);
            logger.info({ count: projects.length }, "listed locked projects");
            return projects.flatMap(({ id, name }) =>
              (["read", "write"] as const).map((level) => ({
                key: `${level}:${id}`,
                value: `${name} (${level})`,
                group: name,
              }))
            );
          } finally {
            await signOut(admin);
          }
        }
        default:
          throw throwAssertNever(type);
      }
    },
  }));
