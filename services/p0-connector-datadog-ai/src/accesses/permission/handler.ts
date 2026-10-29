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

import {
  type DatadogAuth,
  createServiceAccessToken,
  findServiceAccessTokenId,
  listUserPermissions,
  revokeServiceAccessToken,
  updateServiceAccessTokenScopes,
} from "../../datadog/datadog-api.ts";
import { getAdminKeys } from "../../secrets.ts";
import { spec } from "./definition.ts";

type ResourceSchema = ResourceRootSchemaOf<typeof spec>;
type RequestContext = ResourceSchema["RequestContext"];
type OrganizationContext = ResourceSchema["ListerQuery"]["context"];

const secretRef = (secretArn: string) => secretArn as SecretRef;

const secretManagerConfig = (
  secrets: OrganizationContext["secrets"]
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

const createSecretManager = async (context: OrganizationContext) => {
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

/** The secret manager, plus the admin keys that create and revoke grant tokens. */
const newOrganizationClients = async (context: OrganizationContext) => {
  const secretManager = await createSecretManager(context);
  const adminKeys = await getAdminKeys(
    secretManager,
    secretRef(context.secrets.adminKeysSecretId)
  );
  const auth: DatadogAuth = { site: context.site, ...adminKeys };
  return { secretManager, auth };
};

/** The name of the grant's token. The secret holds only the token, so the
 * connector finds the token's id by this name. */
const tokenNameFor = (userId: ResourceSchema["UserId"]) => `P0 ${userId}`;

/**
 * Gives the grant's token exactly `scopes`. The first call creates the token
 * and writes it to the secret; later calls change the scopes in place, and an
 * empty `scopes` revokes the token.
 */
const setGrantScopes = async (
  log: Logger,
  context: RequestContext,
  userId: ResourceSchema["UserId"],
  policies: ResourceSchema["Policy"][]
) => {
  if (policies.length !== 1) {
    log.error(
      { nPolicies: policies.length },
      "expected exactly 1 policy for Datadog token scopes"
    );
    // "unknown" rather than "validation_error": this is a control-plane bug,
    // not a problem with the user's request.
    throw new ConnectorError({
      type: "unknown",
      message:
        "Invalid parameters for Datadog token scopes, expected exactly 1 policy",
      payload: { requestId: context.requestId, nPolicies: policies.length },
    });
  }

  const [{ scopes }] = policies;
  const { serviceAccountId } = context;
  const ref = secretRef(userId);
  const name = tokenNameFor(userId);
  const { secretManager, auth } = await newOrganizationClients(context);
  const tokenId = await findServiceAccessTokenId(auth, {
    serviceAccountId,
    name,
  });

  // Datadog refuses a token with no scopes, and no scopes means no access.
  if (scopes.length === 0) {
    if (tokenId) {
      await revokeServiceAccessToken(auth, { serviceAccountId, tokenId });
      log.info({ tokenId }, "revoked service access token; no scopes remain");
    }
    return;
  }

  // The connector cannot read a grant secret back (its role lacks
  // secretmanager.versions.access), so an existing token is trusted to be the
  // secret's value.
  if (tokenId) {
    await updateServiceAccessTokenScopes(auth, {
      serviceAccountId,
      tokenId,
      scopes,
    });
    log.info(
      { tokenId, nScopes: scopes.length },
      "updated service access token scopes"
    );
    return;
  }

  const token = await createServiceAccessToken(auth, {
    serviceAccountId,
    name,
    scopes,
  });
  try {
    await secretManager.createSecretVersion({
      ref,
      type: "value",
      value: Buffer.from(token.key),
    });
  } catch (error) {
    // Revoke the token that this call made, so that a failed grant does not
    // leave a valid token that no secret holds.
    await revokeServiceAccessToken(auth, {
      serviceAccountId,
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
    { tokenId: token.id, nScopes: scopes.length },
    "created service access token and stored it in the secret"
  );
};

/**
 * Datadog token lifecycle
 *
 * The abstract "user" of the resource-root paradigm is the grant's secret. It
 * holds one service access token, which belongs to a P0 service account and is
 * named after the secret. Its policies are the token's scopes.
 *
 * The token does not expire. A revoke is the only thing that removes access,
 * so every revoke failure propagates.
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
        // Return the ref, as createUser does: the token's name holds it, so
        // both must give the same user id.
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
      const ref = secretRef(userId);
      const { secretManager, auth } = await newOrganizationClients(context);
      const tokenId = await findServiceAccessTokenId(auth, {
        serviceAccountId: context.serviceAccountId,
        name: tokenNameFor(userId),
      });
      // Revoke the token before deleting the secret, so that a failed revoke
      // leaves the secret for the retry.
      if (tokenId) {
        await revokeServiceAccessToken(auth, {
          serviceAccountId: context.serviceAccountId,
          tokenId,
        });
        logger.info({ tokenId }, "revoked service access token");
      }
      await secretManager.deleteSecret({ ref });
      logger.info("deleted secret");
    },

    setPoliciesForUser: async (context, userId, _user, policies) => {
      const logger = ctx.logger.child({ userId, requestId: context.requestId });
      await setGrantScopes(logger, context, userId, policies);
    },

    list: async ({ type, context }) => {
      const logger = ctx.logger.child({
        serviceAccountId: context.serviceAccountId,
      });
      switch (type) {
        case "scope": {
          const { auth } = await newOrganizationClients(context);
          const permissions = await listUserPermissions(
            auth,
            context.serviceAccountId
          );
          logger.info(
            { count: permissions.length },
            "listed service account permissions"
          );
          // A token can hold only scopes that its service account's roles grant.
          return permissions.map(({ name }) => ({ key: name, value: name }));
        }
        default:
          throw throwAssertNever(type);
      }
    },
  }));
