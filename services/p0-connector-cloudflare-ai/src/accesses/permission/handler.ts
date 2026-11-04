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
  SecretNotFoundError,
  type SecretRef,
  createSecretManagerClient,
} from "@p0security/connector-secret-manager-client";

import {
  type CloudflareClient,
  type ListedToken,
  newCloudflareApi,
  newCloudflareClient,
} from "../../cloudflare/cloudflare-api.ts";
import { toConnectorError } from "../../cloudflare/errors.ts";
import { readToken, secretManagerConfigOf } from "../../secrets.ts";
import { spec } from "./definition.ts";
import { toTokenPolicies, zoneNamesOf } from "./token-body.ts";

type ResourceSchema = ResourceRootSchemaOf<typeof spec>;
type RequestContext = ResourceSchema["RequestContext"];

const secretRef = (secretArn: string) => secretArn as SecretRef;

const createSecretManager = async (context: RequestContext) => {
  try {
    return await createSecretManagerClient(
      secretManagerConfigOf(context.secret)
    );
  } catch {
    throw new ConnectorError({
      type: "validation_error",
      message: "Invalid secret manager",
      payload: { manager: context.secret.manager },
    });
  }
};

/** The secret manager, plus Cloudflare as the install token. */
const newAccountClients = async (context: RequestContext, logger: Logger) => {
  const secretManager = await createSecretManager(context);
  const token = await readToken(context.secret, logger);
  const cloudflare = newCloudflareClient(
    newCloudflareApi({ logger, token }),
    context.accountId
  );
  return { secretManager, cloudflare };
};

/** The name of the grant's token. The secret holds only the token, so the
 * connector finds the token's id by this name. */
const tokenNameFor = (userId: ResourceSchema["UserId"]) => `P0 ${userId}`;

/** The account's tokens with the grant's name. Cloudflare lists no expired token. */
const findGrantTokens = async (
  cloudflare: CloudflareClient,
  userId: ResourceSchema["UserId"]
) => {
  const name = tokenNameFor(userId);
  const tokens = await cloudflare.listTokens();
  return tokens.filter((token) => token.name === name);
};

const deleteTokens = async (
  log: Logger,
  cloudflare: CloudflareClient,
  tokens: ListedToken[]
) => {
  for (const { id } of tokens) {
    await cloudflare.deleteToken(id);
    log.info({ tokenId: id }, "deleted grant token");
  }
};

/**
 * Gives the grant's token exactly the policy's resources, until its expiry.
 * The first call mints the token and writes it to the secret; later calls
 * change the token in place, and no resources deletes it.
 */
const setGrantPolicies = async (
  log: Logger,
  context: RequestContext,
  userId: ResourceSchema["UserId"],
  policies: ResourceSchema["Policy"][]
) => {
  if (policies.length !== 1) {
    log.error(
      { nPolicies: policies.length },
      "expected exactly 1 policy for Cloudflare grant tokens"
    );
    // "unknown" rather than "validation_error": this is a control-plane bug,
    // not a problem with the user's request.
    throw new ConnectorError({
      type: "unknown",
      message:
        "Invalid parameters for Cloudflare grant tokens, expected exactly 1 policy",
      payload: { requestId: context.requestId, nPolicies: policies.length },
    });
  }

  const [policy] = policies;
  const { accountId } = context;
  const name = tokenNameFor(userId);
  const { secretManager, cloudflare } = await newAccountClients(context, log);
  const found = await findGrantTokens(cloudflare, userId);

  if (!("expiresOn" in policy)) {
    await deleteTokens(log, cloudflare, found);
    return;
  }

  const zoneNames = zoneNamesOf(policy.resources);
  const zoneIds = new Map(
    zoneNames.length === 0
      ? []
      : (await cloudflare.listZones()).map(({ id, name }) => [name, id])
  );
  const { policies: tokenPolicies, missingZones } = toTokenPolicies(
    accountId,
    policy.resources,
    zoneIds
  );
  // A zone removed from the account must not block later changes.
  if (missingZones.length > 0) {
    log.warn(
      { missingZones },
      "left out the resources of zones the account no longer has"
    );
  }
  // Cloudflare refuses a token with no policies, and no policies means no access.
  if (tokenPolicies.length === 0) {
    await deleteTokens(log, cloudflare, found);
    return;
  }

  const tokenSpec = {
    expiresOn: policy.expiresOn,
    name,
    policies: tokenPolicies,
  };

  // The connector cannot read a grant secret back, so one token is trusted to
  // be the secret's value.
  const [only, ...others] = found;
  if (only !== undefined && others.length === 0) {
    await cloudflare.updateToken(only.id, tokenSpec);
    log.info(
      { tokenId: only.id, nPolicies: tokenPolicies.length },
      "updated grant token"
    );
    return;
  }

  // With more than one token, the secret's value is unknown. Mint and write
  // before the old tokens are deleted, so a failed delete leaves the secret
  // with a valid token, and a rerun finds more than one token again.
  const token = await cloudflare.createToken(tokenSpec);
  try {
    await secretManager.createSecretVersion({
      ref: secretRef(userId),
      type: "value",
      value: Buffer.from(token.value),
    });
  } catch (error) {
    // Delete the token that this call made, so that a failed grant does not
    // leave a valid token that no secret holds.
    await cloudflare
      .deleteToken(token.id)
      .catch((deleteError: unknown) =>
        log.error(
          { tokenId: token.id, error: toConnectorError(deleteError) },
          "failed to delete the token of a failed grant; it stays valid until it expires or is deleted"
        )
      );
    throw error;
  }
  log.info(
    { tokenId: token.id, nPolicies: tokenPolicies.length },
    "minted grant token and stored it in the secret"
  );
  await deleteTokens(log, cloudflare, found);
};

const rethrowMapped = (error: unknown): never => {
  throw toConnectorError(error);
};

/**
 * Cloudflare grant token lifecycle
 *
 * The abstract "user" of the resource-root paradigm is the grant's secret. It
 * holds one account-owned token, minted by the install token and named after
 * the secret. Its policies are the token's resources and permission groups.
 *
 * The token expires at the policy's `expiresOn`. A revoke ends access before
 * that, so every revoke failure propagates.
 *
 * The P0 control plane must serialize calls for the same secret.
 */
export const router = (t: AnyConnectorTRPCInstance) =>
  newResourceRootRouter<ResourceSchema>(t, spec, (ctx: ConnectorContext) => ({
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
      const { secretManager, cloudflare } = await newAccountClients(
        context,
        logger
      );
      // Delete the tokens before the secret, so that a failed delete leaves
      // the secret for the retry.
      await findGrantTokens(cloudflare, userId)
        .then((found) => deleteTokens(logger, cloudflare, found))
        .catch(rethrowMapped);
      await secretManager.deleteSecret({ ref: secretRef(userId) });
      logger.info("deleted secret");
    },

    setPoliciesForUser: async (context, userId, _user, policies) => {
      const logger = ctx.logger.child({ userId, requestId: context.requestId });
      await setGrantPolicies(logger, context, userId, policies).catch(
        rethrowMapped
      );
    },

    list: async ({ type }) => {
      throw throwAssertNever(type);
    },
  }));
