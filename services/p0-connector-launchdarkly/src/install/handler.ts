import {
  type AnyConnectorTRPCInstance,
  ConnectorError,
  type ConnectorErrorOptions,
  type Logger,
  withRouteLogging,
} from "@p0security/connector";

import { type InstallInput, hostOf, installInput } from "../account.ts";
import { ALLOWLIST_PROBLEMS, compileAllowlist } from "../allowlist.ts";
import { newLaunchDarklyApi } from "../launchdarkly/api.ts";
import {
  type CallerIdentity,
  type LaunchDarklyClient,
  newLaunchDarklyClient,
} from "../launchdarkly/client.ts";
import { toConnectorError } from "../launchdarkly/errors.ts";
import { readToken } from "../secrets.ts";
import type { InstallValidation } from "./definition.ts";

/** The checks, by the name a failure reports in `payload.step`. */
type Step = "authenticate" | "domains" | "secret";

/**
 * The error for a failed check. The answer carries facts, not results, so a
 * failure is thrown, and `payload.step` is how P0 tells one from another.
 * `payload.host` says which instance was being validated.
 */
const failedCheck = ({
  step,
  host,
  type,
  message,
  payload,
}: Pick<ConnectorErrorOptions, "message" | "type"> &
  Partial<Pick<ConnectorErrorOptions, "payload">> & {
    step: Step;
    host: string;
  }) =>
  new ConnectorError({ message, payload: { ...payload, host, step }, type });

/**
 * The failure of a LaunchDarkly call at `step`, as P0 shows it: the mapped
 * error, with the step and the host.
 */
const failedAt = (step: Step, host: string, error: unknown): unknown => {
  const mapped = toConnectorError(error, host);
  return mapped instanceof ConnectorError
    ? failedCheck({ ...mapped.data, host, step })
    : mapped;
};

/**
 * `authenticate`: LaunchDarkly accepts the token, and says which account and
 * member it belongs to (`GET /caller-identity`).
 */
const authenticate = (
  client: LaunchDarklyClient,
  host: string
): Promise<CallerIdentity> =>
  client.fetchCallerIdentity().catch((error: unknown) => {
    throw failedAt("authenticate", host, error);
  });

/**
 * `domains`: `DOMAIN_ALLOW_PATTERN`, less the whitespace around it. Install
 * validation reports it, so the installer can show which domains the
 * connector serves, and fails without one that compiles: the accesses would
 * refuse every request.
 *
 * The failure's message never quotes the regex engine's message, which
 * quotes the pattern. The warning in the connector's log has it.
 */
const requireDomainPattern = (host: string, logger: Logger): string => {
  const allowlist = compileAllowlist();
  if (!allowlist.ok) {
    const { problem } = allowlist;
    logger.warn(
      { problem },
      "the email domain allowlist is unusable, so install validation fails"
    );
    throw failedCheck({
      host,
      message: `${ALLOWLIST_PROBLEMS[problem.reason].sentences} Set it to a regular expression for the email domains that may receive access.`,
      step: "domains",
      type: "validation_error",
    });
  }
  return allowlist.pattern;
};

/**
 * Install validation, in order, each failure thrown with its step:
 *
 * 1. `secret`: the connector can read the access token from the secret.
 * 2. `authenticate`: LaunchDarkly accepts the token, and says which account
 *    it belongs to, and which member a personal token acts as.
 * 3. `domains`: `DOMAIN_ALLOW_PATTERN` is set, and compiles.
 *
 * It reports the account's id, the token's kind and member, and the
 * pattern. Nothing of the token is reported.
 */
export const getInstallValidation = async (
  { instance, secret }: InstallInput,
  logger: Logger
): Promise<InstallValidation> => {
  const host = hostOf({ instance });
  const atStep = (step: Step) => (error: unknown) => {
    throw error instanceof ConnectorError
      ? failedCheck({ ...error.data, host, step })
      : error;
  };
  const client = await readToken(secret, logger)
    .then((token) =>
      newLaunchDarklyClient(newLaunchDarklyApi({ instance, logger, token }))
    )
    .catch(atStep("secret"));
  const { accountId, tokenKind, tokenOwnerMemberId } = await authenticate(
    client,
    host
  );
  const domainPattern = requireDomainPattern(host, logger);
  return { accountId, domainPattern, tokenKind, tokenOwnerMemberId };
};

export const router = (t: AnyConnectorTRPCInstance) => {
  const { router } = t;
  const procedure = withRouteLogging(t.procedure);

  return router({
    get: procedure.input(installInput.parse).query(async ({ input, ctx }) => {
      const validation = await getInstallValidation(input, ctx.logger);
      ctx.logger.info(
        { instance: input.instance, ...validation },
        "validated the LaunchDarkly account"
      );
      return validation;
    }),
  });
};
