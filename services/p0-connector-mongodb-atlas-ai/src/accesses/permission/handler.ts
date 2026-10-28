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
} from "@p0security/secret-manager-client";
import { createHash } from "node:crypto";

import {
  type AtlasClient,
  newAtlasClient,
  requestToken,
} from "../../atlas/atlas-api.ts";
import { atlasProjectRoles } from "../../atlas/roles.ts";
import { getClientSecret } from "../../secrets.ts";
import { spec } from "./definition.ts";

type ResourceSchema = ResourceRootSchemaOf<typeof spec>;
type RequestContext = ResourceSchema["RequestContext"];
type ProjectContext = ResourceSchema["ListerQuery"]["context"];

const secretRef = (secretArn: string) => secretArn as SecretRef;

const secretManagerConfig = (
  secrets: ProjectContext["secrets"]
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

const createSecretManager = async (context: ProjectContext) => {
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

/** The secret manager, and an Atlas client for the project that acts as the
 * admin service account. */
const newProjectClients = async (context: ProjectContext) => {
  const secretManager = await createSecretManager(context);
  const clientSecret = await getClientSecret(
    secretManager,
    secretRef(context.secrets.clientSecretSecretId)
  );
  const token = await requestToken(
    { clientId: context.clientId, clientSecret },
    "admin token request"
  );
  return {
    secretManager,
    atlas: newAtlasClient(token, context.atlasProjectId),
  };
};

/** The grant's MCP configuration name: a hash of the grant's secret. */
const mcpConfigNameFor = (userId: ResourceSchema["UserId"]) =>
  `p0-${createHash("sha256").update(userId).digest("hex").slice(0, 32)}`;

const sameRoles = (a: string[], b: string[]) =>
  [...a].sort().join(" ") === [...b].sort().join(" ");

/**
 * Gets a new token for the configuration with a new secret, and deletes its
 * other secrets after the token is stored. A configuration holds at most 2
 * secrets, so make room first.
 */
const rotateToken = async (
  atlas: AtlasClient,
  mcpConfigId: string,
  clientId: string,
  store: (token: string) => Promise<void>
) => {
  const existing = (await atlas.listMcpConfigSecrets(mcpConfigId)).sort(
    (a, b) => a.createdAt.localeCompare(b.createdAt)
  );
  const kept = existing.at(-1);
  for (const { id } of existing.slice(0, -1)) {
    await atlas.deleteMcpConfigSecret(mcpConfigId, id);
  }
  const { secret } = await atlas.createMcpConfigSecret(mcpConfigId);
  await store(await requestToken({ clientId, clientSecret: secret }));
  if (kept) await atlas.deleteMcpConfigSecret(mcpConfigId, kept.id);
};

/**
 * Gives the grant's MCP configuration exactly the requested roles, then writes
 * a new token for it to the grant's secret.
 */
const setGrantRoles = async (
  log: Logger,
  context: RequestContext,
  userId: ResourceSchema["UserId"],
  policies: ResourceSchema["Policy"][]
) => {
  if (policies.length !== 1) {
    log.error(
      { nPolicies: policies.length },
      "expected exactly 1 policy for Atlas project roles"
    );
    // "unknown" rather than "validation_error": this is a control-plane bug,
    // not a problem with the user's request.
    throw new ConnectorError({
      type: "unknown",
      message:
        "Invalid parameters for Atlas project roles, expected exactly 1 policy",
      payload: { requestId: context.requestId, nPolicies: policies.length },
    });
  }

  const [{ roles }] = policies;
  // The control plane calls deleteUser next, which deletes the configuration.
  if (roles.length === 0) {
    log.info("no roles remain; the configuration is deleted next");
    return;
  }

  const { secretManager, atlas } = await newProjectClients(context);
  const name = mcpConfigNameFor(userId);
  const existing = await atlas.findMcpConfig(name);
  const config = existing ?? (await atlas.createMcpConfig(name, roles));
  if (!existing) {
    log.info({ mcpConfigId: config.mcpConfigId }, "created MCP configuration");
  } else if (!sameRoles(existing.roles, roles)) {
    await atlas.setMcpConfigRoles(config.mcpConfigId, roles);
    log.info({ mcpConfigId: config.mcpConfigId, roles }, "changed roles");
  }

  await rotateToken(
    atlas,
    config.mcpConfigId,
    config.clientId,
    async (token) => {
      await secretManager.createSecretVersion({
        ref: secretRef(userId),
        type: "value",
        value: Buffer.from(token),
      });
    }
  );
  log.info(
    { mcpConfigId: config.mcpConfigId, nRoles: roles.length },
    "stored a new MCP token in the secret"
  );
};

/**
 * Atlas MCP configuration lifecycle
 *
 * The abstract "user" of the resource-root paradigm is the grant's secret. It
 * holds an access token for the Atlas-hosted MCP server. The token belongs to
 * an MCP configuration that P0 creates in the project for the grant. Its
 * policies are the configuration's project roles.
 *
 * Deleting the configuration, or its secret, ends its tokens at once. A revoke
 * is the only thing that removes access, so every revoke failure propagates.
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
        // Return the ref, as createUser does: the configuration's name is
        // derived from it, so both must give the same user id.
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
      const { secretManager, atlas } = await newProjectClients(context);
      // Delete the configuration before the secret, so that a failed delete
      // leaves the secret for the retry.
      const config = await atlas.findMcpConfig(mcpConfigNameFor(userId));
      if (config) {
        await atlas.deleteMcpConfig(config.mcpConfigId);
        logger.info(
          { mcpConfigId: config.mcpConfigId },
          "deleted MCP configuration"
        );
      }
      await secretManager.deleteSecret({ ref: secretRef(userId) });
      logger.info("deleted secret");
    },

    setPoliciesForUser: async (context, userId, _user, policies) => {
      const logger = ctx.logger.child({ userId, requestId: context.requestId });
      await setGrantRoles(logger, context, userId, policies);
    },

    list: async ({ type }) => {
      switch (type) {
        case "role":
          return Object.entries(atlasProjectRoles).map(([key, value]) => ({
            key,
            value,
          }));
        default:
          throw throwAssertNever(type);
      }
    },
  }));
