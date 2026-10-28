import {
  type AnyConnectorTRPCInstance,
  ConnectorError,
  type ConnectorErrorOptions,
  type Logger,
  withRouteLogging,
} from "@p0security/connector-core";

import {
  type Instance,
  hostOf,
  instance,
} from "../accesses/project-role/definition.ts";
import {
  ALLOWED_EMAIL_DOMAIN_PATTERN_ENV,
  compileAllowlist,
} from "../allowlist.ts";
import { isStatus } from "../harbor/api.ts";
import { type HarborClient, harborClientFor } from "../harbor/client.ts";
import { notHarborAdmin, toConnectorError } from "../harbor/errors.ts";
import { mintIdToken } from "../harbor/oidc.ts";
import {
  MINIMUM_HARBOR_VERSION,
  formatHarborVersion,
  isSupportedHarborVersion,
  parseHarborVersion,
} from "../harbor/version.ts";
import { readAdminCredential } from "../secrets.ts";
import type { InstallValidation } from "./definition.ts";

/** The checks, by the name a failure reports in `payload.step`. */
type Step = "authenticate" | "pattern" | "secret" | "sign_in" | "systeminfo";

/**
 * The one auth mode the connector supports. Harbor accepts an ID token on
 * its API only in OIDC mode, and with `db_auth` users set their own,
 * unverified email, which is what the connector matches on (INT-231).
 */
const SUPPORTED_AUTH_MODE = "oidc_auth";

// Harbor's other auth modes, which a message may name. Anything else is
// whatever answered, and isn't quoted.
const REFUSED_AUTH_MODES: ReadonlySet<string> = new Set([
  "db_auth",
  "ldap_auth",
  "uaa_auth",
  "http_auth",
]);

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
  new ConnectorError({ type, message, payload: { ...payload, step, host } });

/**
 * `ALLOWED_EMAIL_DOMAIN_PATTERN`, less the whitespace around it. Install
 * validation reports it, so the installer can show which domains the
 * connector serves, and fails without one that compiles: the accesses would
 * refuse every request.
 *
 * The failure's message never quotes the regex engine's message, which
 * quotes the pattern. The warning in the connector's log has it.
 */
const requireAllowedEmailDomainPattern = (
  host: string,
  logger: Logger
): string => {
  const allowlist = compileAllowlist();
  if (!allowlist.ok) {
    const { problem } = allowlist;
    logger.warn(
      { problem },
      "the email domain allowlist is unusable; install validation fails"
    );
    throw failedCheck({
      step: "pattern",
      host,
      type: "validation_error",
      message: `${
        problem.reason === "unset"
          ? `The connector's ${ALLOWED_EMAIL_DOMAIN_PATTERN_ENV} isn't set.`
          : `The connector's ${ALLOWED_EMAIL_DOMAIN_PATTERN_ENV} isn't a regular expression that compiles. The connector's log says why.`
      } Set it to a regular expression for the email domains that may receive access.`,
    });
  }
  return allowlist.pattern;
};

/**
 * The failure of a Harbor call at `step`, as P0 shows it: the mapped error,
 * with the step and the host.
 */
const failedAt = (step: Step, host: string, error: unknown): unknown => {
  const mapped = toConnectorError(error, host);
  return mapped instanceof ConnectorError
    ? failedCheck({ ...mapped.data, step, host })
    : mapped;
};

/**
 * Asks Harbor for its system info. Harbor answers this route for anyone, so
 * it proves the connector reaches something that answers as Harbor does, and
 * nothing about the credential.
 */
const readSystemInfo = (harbor: HarborClient, host: string) =>
  harbor.systemInfo().catch((error: unknown) => {
    // Since Harbor answers anyone, a refusal comes from something in front
    // of it.
    const status = [401, 403].find((refusal) => isStatus(error, refusal));
    if (status !== undefined) {
      throw failedCheck({
        step: "systeminfo",
        host,
        type: "insufficient_privileges",
        message: `Something in front of Harbor at ${host} refused the connector's call with ${status}: Harbor itself answers GET /api/v2.0/systeminfo for anyone. Let the connector through the proxy or gateway in front of the instance.`,
        payload: { status },
      });
    }
    throw failedAt("systeminfo", host, error);
  });

/**
 * Refuses a Harbor older than the connector's floor, and a version that
 * doesn't read as one.
 * The message quotes the numbers it parsed, never the text Harbor sent.
 */
const requireSupportedVersion = (harborVersion: string, host: string) => {
  const version = parseHarborVersion(harborVersion);
  if (version === undefined) {
    throw failedCheck({
      step: "systeminfo",
      host,
      type: "validation_error",
      message: `Harbor at ${host} reports a version the connector can't read. It needs Harbor ${formatHarborVersion(MINIMUM_HARBOR_VERSION)} or later.`,
    });
  }
  if (!isSupportedHarborVersion(version)) {
    throw failedCheck({
      step: "systeminfo",
      host,
      type: "validation_error",
      message: `Harbor at ${host} is version ${formatHarborVersion(version)}. The connector needs Harbor ${formatHarborVersion(MINIMUM_HARBOR_VERSION)} or later.`,
      payload: { harborVersion: formatHarborVersion(version) },
    });
  }
};

/**
 * Refuses an auth mode other than OIDC: Harbor accepts the admin user's ID
 * token only in OIDC mode, and LDAP mode is no longer supported.
 */
const requireOidc = (authMode: string, host: string) => {
  if (authMode === SUPPORTED_AUTH_MODE) return;
  const named = REFUSED_AUTH_MODES.has(authMode);
  throw failedCheck({
    step: "systeminfo",
    host,
    type: "validation_error",
    message: `Harbor at ${host} signs users in with ${named ? authMode : "an auth mode the connector doesn't know"}. The connector signs in to Harbor with an OIDC ID token, so it supports ${SUPPORTED_AUTH_MODE} only.`,
    payload: named ? { authMode } : {},
  });
};

/**
 * Proves Harbor accepts the ID token, and that the user it signs in as is a
 * Harbor system administrator by its own `sysadmin_flag`: `GET /users/current`
 * answers 200 with the flag set. A 401 is the `admin_token_rejected` refusal,
 * and an unset flag `admin_not_harbor_admin`.
 *
 * The flag, not the identity provider's admin group: the connector holds the
 * account to what a Harbor admin can see on the Users page. The body, which
 * holds the user's CLI secret in OIDC mode, is dropped by the client's parse.
 */
const requireHarborAdmin = async (harbor: HarborClient, host: string) => {
  const { sysadminFlag } = await harbor
    .currentUserAdmin()
    .catch((error: unknown) => {
      throw failedAt("authenticate", host, error);
    });
  if (!sysadminFlag) {
    throw failedCheck({
      ...notHarborAdmin(host).data,
      step: "authenticate",
      host,
    });
  }
};

/**
 * The checks on Harbor, in order, each failing at its step:
 *
 * 1. `systeminfo`: one call, which the instance answers as Harbor does.
 *    When the answer carries a version, one below the floor fails here. The
 *    auth mode must be `oidc_auth`.
 * 2. `authenticate`: Harbor accepts the ID token, and its user has
 *    `sysadmin_flag` ({@link requireHarborAdmin}).
 * 3. `systeminfo`: the answer carried a version, as Harbor's does for any
 *    caller it accepted.
 *
 * An administrator holds every permission the accesses use, so nothing more
 * is probed.
 */
export const checkHarbor = async ({
  harbor,
  host,
}: {
  harbor: HarborClient;
  host: string;
}): Promise<Pick<InstallValidation, "authMode" | "harborVersion">> => {
  const { authMode, harborVersion } = await readSystemInfo(harbor, host);
  if (harborVersion !== undefined) {
    requireSupportedVersion(harborVersion, host);
  }
  requireOidc(authMode, host);
  await requireHarborAdmin(harbor, host);
  // Harbor tells every caller it authenticated its version.
  if (harborVersion === undefined) {
    throw failedCheck({
      step: "systeminfo",
      host,
      type: "validation_error",
      message: `Harbor at ${host} accepted the admin account's ID token but didn't report its version, which every Harbor the connector supports does. Check that the instance's URL points at Harbor itself, not at a proxy that changes its answers.`,
    });
  }
  return { authMode, harborVersion };
};

/**
 * Install validation, in order: the connector can read the instance's admin
 * credential (`secret`), it has a pattern that compiles (`pattern`), the
 * identity provider mints an ID token from the credential (`sign_in`), and
 * Harbor passes {@link checkHarbor}. It reports Harbor's version and auth
 * mode, and the pattern. Nothing of the credential or the token is reported.
 */
export const getInstallValidation = async (
  { url, secret: pointer }: Instance,
  logger: Logger
): Promise<InstallValidation> => {
  const host = hostOf({ url });
  const atStep = (step: Step) => (error: unknown) => {
    throw error instanceof ConnectorError
      ? failedCheck({ ...error.data, step, host })
      : error;
  };
  const credential = await readAdminCredential(pointer, logger).catch(
    atStep("secret")
  );
  const allowedEmailDomainPattern = requireAllowedEmailDomainPattern(
    host,
    logger
  );
  const idToken = await mintIdToken({ credential, host, logger }).catch(
    atStep("sign_in")
  );
  const harbor = harborClientFor({ url, idToken, logger });
  return {
    ...(await checkHarbor({ harbor, host })),
    allowedEmailDomainPattern,
  };
};

export const router = (t: AnyConnectorTRPCInstance) => {
  const { router } = t;
  // Logs each validation and its failure, as the access routes do.
  const procedure = withRouteLogging(t.procedure);

  return router({
    get: procedure.input(instance.parse).query(async ({ input, ctx }) => {
      const validation = await getInstallValidation(input, ctx.logger);
      ctx.logger.info(
        { url: input.url, ...validation },
        "validated the Harbor instance"
      );
      return validation;
    }),
  });
};
