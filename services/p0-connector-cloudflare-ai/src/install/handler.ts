import {
  type AnyConnectorTRPCInstance,
  ConnectorError,
  type ConnectorErrorOptions,
  type Logger,
  withRouteLogging,
} from "@p0security/connector-core";

import { type Account, account } from "../account.ts";
import {
  type CloudflareClient,
  type CloudflareToken,
  type TokenPolicy,
  newCloudflareApi,
  newCloudflareClient,
} from "../cloudflare/cloudflare-api.ts";
import { toConnectorError } from "../cloudflare/errors.ts";
import { readToken } from "../secrets.ts";
import { type InstallValidation, REQUIRED_GROUPS } from "./definition.ts";

/** The checks, by the name a failure reports in `payload.step`. */
type Step = "groups" | "secret" | "verify";

const failedCheck = ({
  step,
  type,
  message,
  payload,
}: Pick<ConnectorErrorOptions, "message" | "type"> &
  Partial<Pick<ConnectorErrorOptions, "payload">> & { step: Step }) =>
  new ConnectorError({ message, payload: { ...payload, step }, type });

/** The failure of a Cloudflare call at `step`, as P0 shows it. */
const failedAt = (step: Step) => (error: unknown) => {
  const mapped = toConnectorError(error);
  throw mapped instanceof ConnectorError
    ? failedCheck({ ...mapped.data, step })
    : mapped;
};

const ALL_ZONES = "com.cloudflare.api.account.zone.*";

/**
 * Whether `policy` grants its groups on the whole account. A zone group
 * may also nest all of the account's zones under it.
 */
const coversAccount = (
  { effect, resources }: TokenPolicy,
  accountId: string,
  zoneGroup: boolean
) => {
  const granted = resources[`com.cloudflare.api.account.${accountId}`];
  if (effect !== "allow" || granted === undefined) return false;
  if (granted === "*") return true;
  return zoneGroup && granted[ALL_ZONES] === "*";
};

/**
 * `groups`: the token holds every group in {@link REQUIRED_GROUPS} on the
 * whole account. Returns the names of its other groups.
 */
const checkGroups = (
  { policies }: CloudflareToken,
  accountId: string
): string[] => {
  const required = Object.values(REQUIRED_GROUPS);
  const missing = required.filter(
    ({ id }) =>
      !policies.some(
        (policy) =>
          coversAccount(
            policy,
            accountId,
            id === REQUIRED_GROUPS.zoneRead.id
          ) && policy.permission_groups.some((group) => group.id === id)
      )
  );
  if (missing.length > 0) {
    const labels = missing.map(({ label }) => label).join(" and ");
    throw failedCheck({
      message: `The install token is missing ${labels}. Give the token ${missing.length === 1 ? "that group" : "those groups"} in the Cloudflare dashboard, then try again.`,
      payload: { missingGroups: missing.map(({ id }) => id).join(",") },
      step: "groups",
      type: "insufficient_privileges",
    });
  }
  const requiredIds = new Set<string>(required.map(({ id }) => id));
  const others = new Set(
    policies.flatMap(({ permission_groups }) =>
      permission_groups
        .filter(({ id }) => !requiredIds.has(id))
        .map(({ id, name }) => name ?? id)
    )
  );
  return [...others].sort();
};

/**
 * `verify`: Cloudflare accepts the token on this account and says it is
 * active. Returns the token's id.
 */
const verify = async (client: CloudflareClient): Promise<string> => {
  const { id, status } = await client.verifyToken().catch(failedAt("verify"));
  if (status !== "active") {
    throw failedCheck({
      message: `Cloudflare says the install token is ${status}, not active. Make a new install token, store it in the secret, and try again.`,
      payload: { status },
      step: "verify",
      type: "insufficient_privileges",
    });
  }
  return id;
};

/**
 * Install validation, in order, each failure thrown with its step:
 *
 * 1. `secret`: the connector can read the install token from the secret.
 * 2. `verify`: Cloudflare accepts the token on the account, and it is
 *    active.
 * 3. `groups`: the token holds Account API Tokens Edit and Zone Read on the
 *    account. Other groups pass: P0 shows them as a warning.
 *
 * Every check only reads. Nothing of the token is reported.
 */
export const getInstallValidation = async (
  { accountId, secret }: Account,
  logger: Logger
): Promise<InstallValidation> => {
  const client = await readToken(secret, logger)
    .then((token) =>
      newCloudflareClient(newCloudflareApi({ logger, token }), accountId)
    )
    .catch((error: unknown) => {
      throw error instanceof ConnectorError
        ? failedCheck({ ...error.data, step: "secret" })
        : error;
    });
  const tokenId = await verify(client);
  const token = await client.getToken(tokenId).catch(failedAt("groups"));
  const otherGroups = checkGroups(token, accountId);
  if (otherGroups.length > 0) {
    logger.warn(
      { otherGroups },
      "the install token holds groups beyond the two it needs"
    );
  }
  return { otherGroups, tokenId };
};

export const router = (t: AnyConnectorTRPCInstance) => {
  const { router } = t;
  const procedure = withRouteLogging(t.procedure);

  return router({
    get: procedure.input(account.parse).query(async ({ input, ctx }) => {
      const validation = await getInstallValidation(input, ctx.logger);
      ctx.logger.info(validation, "validated the Cloudflare account");
      return validation;
    }),
  });
};
