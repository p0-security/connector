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

import {
  listSupportedScopes,
  requestAppToken,
} from "../../pagerduty/pagerduty-api.ts";
import { getClientSecret } from "../../secrets.ts";
import { spec } from "./definition.ts";

type ResourceSchema = ResourceRootSchemaOf<typeof spec>;
type RequestContext = ResourceSchema["RequestContext"];
type AccountContext = ResourceSchema["ListerQuery"]["context"];

const secretRef = (secretArn: string) => secretArn as SecretRef;

const secretManagerConfig = (
  secrets: AccountContext["secrets"]
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

const createSecretManager = async (context: AccountContext) => {
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

/**
 * Gives the grant a new app token that holds exactly `scopes`, and writes it to
 * the secret. A token's scopes cannot change, so every call gets a new token.
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
      "expected exactly 1 policy for PagerDuty token scopes"
    );
    // "unknown" rather than "validation_error": this is a control-plane bug,
    // not a problem with the user's request.
    throw new ConnectorError({
      type: "unknown",
      message:
        "Invalid parameters for PagerDuty token scopes, expected exactly 1 policy",
      payload: { requestId: context.requestId, nPolicies: policies.length },
    });
  }

  const [{ scopes }] = policies;
  // The control plane calls deleteUser next, which deletes the secret.
  if (scopes.length === 0) {
    log.info("no scopes remain; the secret is deleted next");
    return;
  }

  const secretManager = await createSecretManager(context);
  const clientSecret = await getClientSecret(
    secretManager,
    secretRef(context.secrets.clientSecretSecretId)
  );
  const token = await requestAppToken(
    { clientId: context.clientId, clientSecret },
    { region: context.region, subdomain: context.subdomain, scopes }
  );
  await secretManager.createSecretVersion({
    ref: secretRef(userId),
    type: "value",
    value: Buffer.from(token),
  });
  log.info({ nScopes: scopes.length }, "stored a new app token in the secret");
};

/**
 * PagerDuty app token lifecycle
 *
 * The abstract "user" of the resource-root paradigm is the grant's secret. It
 * holds one PagerDuty app token for the account. Its policies are the token's
 * scopes.
 *
 * PagerDuty documents no way to revoke one app token, so a token stays valid
 * until it expires (1 day), even after a scope change or a revoke replaces or
 * deletes the secret.
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
        // Return the ref, as createUser does, so both give the same user id.
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
      const secretManager = await createSecretManager(context);
      await secretManager.deleteSecret({ ref: secretRef(userId) });
      logger.info("deleted secret");
    },

    setPoliciesForUser: async (context, userId, _user, policies) => {
      const logger = ctx.logger.child({ userId, requestId: context.requestId });
      await setGrantScopes(logger, context, userId, policies);
    },

    list: async ({ type, context }) => {
      const logger = ctx.logger.child({ region: context.region });
      switch (type) {
        case "scope": {
          const scopes = await listSupportedScopes(context.region);
          logger.info({ count: scopes.length }, "listed PagerDuty scopes");
          return scopes.map((scope) => ({ key: scope, value: scope }));
        }
        default:
          throw throwAssertNever(type);
      }
    },
  }));
