import {
  type AnyConnectorTRPCInstance,
  ConnectorError,
  type ConnectorErrorOptions,
  type Logger,
  withRouteLogging,
} from "@p0security/connector";

import { requireAllowedDomains } from "../allowed-domains.ts";
import { type Auth0Client, newAuth0Client } from "../auth0/client.ts";
import { toConnectorError } from "../auth0/errors.ts";
import { missingScopes } from "../auth0/scopes.ts";
import { type TenantCredentials, tenantCredentials } from "../credentials.ts";
import type { InstallValidation } from "./definition.ts";

/** The checks, in the order they run, by the name a failure reports in `payload.step`. */
type Step = "authenticate" | "domains" | "scopes" | "secret";

/**
 * The error for a failed check. The answer carries facts, not results, so a
 * failure is thrown, and `payload.step` is how P0 tells one from another.
 * `payload.tenant` says which tenant was being validated.
 */
const failedCheck = ({
  step,
  tenant,
  type,
  message,
  payload,
}: Pick<ConnectorErrorOptions, "message" | "type"> &
  Partial<Pick<ConnectorErrorOptions, "payload">> & {
    step: Step;
    tenant: string;
  }) =>
  new ConnectorError({ type, message, payload: { ...payload, step, tenant } });

/** Runs one check, naming its step on whatever it fails with. */
const runStep = async <T>(
  step: Step,
  tenant: string,
  check: () => Promise<T>
): Promise<T> => {
  try {
    return await check();
  } catch (error) {
    const mapped = toConnectorError(error, { tenant });
    throw mapped instanceof ConnectorError
      ? failedCheck({ ...mapped.data, step, tenant })
      : mapped;
  }
};

/** `secret`: the connector can read the client secret. */
const checkSecret = (auth0: Auth0Client, tenant: string) =>
  runStep("secret", tenant, () => auth0.readSecret());

/** `authenticate`: the tenant exchanges the client credentials for a Management API token. */
const authenticate = (auth0: Auth0Client, tenant: string) =>
  runStep("authenticate", tenant, () => auth0.exchangeForScopes());

/** `scopes`: the token carries every scope the connector needs. Extra scopes are ignored. */
const checkScopes = (granted: string[], tenant: string) => {
  const missing = missingScopes(granted);
  if (missing.length === 0) return;
  throw failedCheck({
    step: "scopes",
    tenant,
    type: "insufficient_privileges",
    message: `The connector's application on Auth0 tenant ${tenant} is missing ${
      missing.length === 1 ? "a Management API scope" : "Management API scopes"
    }: ${missing.join(", ")}. Authorize the application for the Management API with ${
      missing.length === 1 ? "it" : "them"
    }, then validate again.`,
    payload: { missing: missing.join(" ") },
  });
};

/** `domains`: the connector has a usable `DOMAIN_ALLOW_PATTERN`, which it reports. */
const checkDomains = (tenant: string, logger: Logger): string => {
  try {
    return requireAllowedDomains().pattern;
  } catch (error) {
    // The message names the variable and why. It never holds a secret.
    logger.warn({ error }, "the allowed domains are unusable");
    throw failedCheck({
      step: "domains",
      tenant,
      type: "validation_error",
      message: error instanceof Error ? error.message : String(error),
    });
  }
};

export const getInstallValidation = async (
  credentials: TenantCredentials,
  logger: Logger
): Promise<InstallValidation> => {
  const { tenant } = credentials;
  const auth0 = newAuth0Client({ ...credentials, log: logger });
  await checkSecret(auth0, tenant);
  const scopes = await authenticate(auth0, tenant);
  checkScopes(scopes, tenant);
  const allowedDomains = checkDomains(tenant, logger);
  return { tenant, allowedDomains };
};

export const router = (t: AnyConnectorTRPCInstance) => {
  const { router } = t;
  // Logs each validation and its failure, as the access routes do.
  const procedure = withRouteLogging(t.procedure);

  return router({
    get: procedure
      .input(tenantCredentials.parse)
      .query(async ({ input, ctx }) => {
        const logger = ctx.logger.child({
          tenant: input.tenant,
          clientId: input.clientId,
        });
        const validation = await getInstallValidation(input, logger);
        logger.info(validation, "validated the Auth0 tenant");
        return validation;
      }),
  });
};
