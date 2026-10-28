// Shaped after services/p0-connector-harbor/src/install/handler.ts: a closed
// set of steps, each failure thrown with its step and the host, and one `get`
// query that answers facts about an install that works.
import {
  type AnyConnectorTRPCInstance,
  ConnectorError,
  type ConnectorErrorOptions,
  type Logger,
  withRouteLogging,
} from "@p0security/connector-core";

import { hostOf } from "../accesses/common.ts";
import { policyNotLoaded } from "../accesses/lines.ts";
import {
  ALLOWED_EMAIL_DOMAIN_PATTERN_ENV,
  compileAllowlist,
} from "../allowlist.ts";
import { ArgoCdError, isStatus } from "../argocd/api.ts";
import {
  type ArgoCdClient,
  P0_POLICY_KEY,
  RBAC_CONFIG_MAP,
  type RbacTarget,
  argoCdClientFor,
  managingAppOf,
  rbacTargetOf,
} from "../argocd/client.ts";
import { callArgoCd } from "../argocd/errors.ts";
import {
  CONNECTOR_ACCOUNT,
  goTrim,
  parseP0Line,
  parsePolicy,
} from "../argocd/policy.ts";
import {
  MINIMUM_ARGOCD_VERSION,
  formatArgoCdVersion,
  isSupportedArgoCdVersion,
  parseArgoCdVersion,
} from "../argocd/version.ts";
import { type Instance, instance } from "../instance.ts";
import { readApiToken } from "../secrets.ts";
import { assertLeastPrivilege } from "../self-check.ts";
import type { ArgoCdInstallStep, InstallValidation } from "./definition.ts";

/** The issuer Argo CD gives a local account's tokens. */
const LOCAL_ISSUER = "argocd";

const MINIMUM = formatArgoCdVersion(MINIMUM_ARGOCD_VERSION);

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
    step: ArgoCdInstallStep;
    host: string;
  }) =>
  new ConnectorError({ type, message, payload: { ...payload, step, host } });

/**
 * Runs `run` as `step`: an Argo CD failure is mapped to the error P0 shows,
 * and that error, or a `ConnectorError` thrown along the way, is given the
 * step and the host. Anything else is a bug, and passes as it is.
 */
const at = async <T>(
  step: ArgoCdInstallStep,
  host: string,
  run: () => Promise<T> | T
): Promise<T> => {
  try {
    return await callArgoCd(async () => await run(), host);
  } catch (error) {
    throw error instanceof ConnectorError
      ? failedCheck({ ...error.data, step, host })
      : error;
  }
};

// copy of `requireAllowedEmailDomainPattern` in
// services/p0-connector-harbor/src/install/handler.ts
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
 * `reachable`: Argo CD answers `GET /api/version` for anyone, so an answer
 * proves the connector reaches something that answers as Argo CD does, and
 * nothing about the token. A 401 or 403 comes from something in front of it.
 */
const readVersion = (argocd: ArgoCdClient, host: string) =>
  at("reachable", host, () =>
    argocd.version().catch((error: unknown) => {
      const status = [401, 403].find((refusal) => isStatus(error, refusal));
      if (status === undefined) throw error;
      throw failedCheck({
        step: "reachable",
        host,
        type: "insufficient_privileges",
        message: `Something in front of Argo CD at ${host} refused the connector's call with ${status}: Argo CD itself answers GET /api/version for anyone. Let the connector through the proxy or gateway in front of the instance.`,
        payload: { status },
      });
    })
  );

/**
 * `version`: refuses an Argo CD older than 3.0.0, whose policy can't let an
 * account patch `argocd-rbac-cm` alone, and a version that doesn't read as
 * one. The message quotes the numbers it parsed, never the text Argo CD sent.
 */
const requireSupportedVersion = (text: string, host: string) => {
  const version = parseArgoCdVersion(text);
  if (version === undefined) {
    throw failedCheck({
      step: "version",
      host,
      type: "validation_error",
      message: `Argo CD at ${host} reports a version the connector can't read. It needs Argo CD ${MINIMUM} or later.`,
    });
  }
  if (!isSupportedArgoCdVersion(version)) {
    const argoCdVersion = formatArgoCdVersion(version);
    throw failedCheck({
      step: "version",
      host,
      type: "validation_error",
      message: `Argo CD at ${host} is version ${argoCdVersion}. The connector needs Argo CD ${MINIMUM} or later, the first whose policy can let an account patch argocd-rbac-cm alone. Upgrade Argo CD.`,
      payload: { argoCdVersion },
    });
  }
};

/**
 * `account`: Argo CD takes the token for the `p0-connector` local account.
 * A token it answers as anonymous fails here, before any call whose answer
 * an anonymous caller could get. Who else the token is isn't quoted.
 */
const requireConnectorAccount = async (argocd: ArgoCdClient, host: string) => {
  const { username, issuer } = await at("account", host, () =>
    argocd.userInfo()
  );
  if (username === CONNECTOR_ACCOUNT && issuer === LOCAL_ISSUER) return;
  throw failedCheck({
    step: "account",
    host,
    type: "validation_error",
    message: `The API token in the secret for ${host} isn't the ${CONNECTOR_ACCOUNT} local account's. Generate one with "argocd account generate-token --account ${CONNECTOR_ACCOUNT}" and store it in the secret.`,
  });
};

/**
 * `managing_app`: the account may read the managing Application, and it is
 * in the project the instance names. The client sends no `project`, so this
 * is where the instance's project is held to. The project Argo CD answered
 * isn't quoted.
 */
const requireManagingApp = async (
  argocd: ArgoCdClient,
  input: Instance,
  host: string
) => {
  const { project: expected, app } = managingAppOf(input);
  const { project } = await at("managing_app", host, () =>
    argocd.getApplication(app)
  );
  if (project === expected) return;
  throw failedCheck({
    step: "managing_app",
    host,
    type: "validation_error",
    message: `Application ${app} on ${host} isn't in project ${expected}. Set the managing Application on the Argo CD instance in P0 to <project>/${app}, with the project the Application is in.`,
  });
};

/**
 * `rbac_config_map`: `argocd-rbac-cm`'s keys, read through the managing
 * Application. An Application that doesn't manage it is an install the
 * connector doesn't support.
 */
const readRbacData = (argocd: ArgoCdClient, target: RbacTarget, host: string) =>
  at("rbac_config_map", host, async () => {
    try {
      return (await argocd.readRbacConfigMap(target)).data;
    } catch (error) {
      if (
        error instanceof ArgoCdError &&
        error.failure.kind === "not_managed"
      ) {
        const { app, namespace } = target;
        throw failedCheck({
          step: "rbac_config_map",
          host,
          type: "validation_error",
          message: `Application ${app} on ${host} doesn't manage ConfigMap ${namespace}/${RBAC_CONFIG_MAP}. The connector supports only an Argo CD whose ${RBAC_CONFIG_MAP} an Application deploys: set the managing Application and the namespace on the Argo CD instance in P0 to that Application and ${RBAC_CONFIG_MAP}'s namespace.`,
          payload: { app, namespace },
        });
      }
      throw error;
    }
  });

/**
 * `scopes`: Argo CD matches a `g` line's subject against the token's
 * `scopes` claims, so without `email` the lines P0 writes match no one.
 */
const requireEmailScope = (scopes: string[] | undefined, host: string) => {
  if (scopes === undefined) {
    throw failedCheck({
      step: "scopes",
      host,
      type: "validation_error",
      message: `The connector can't read scopes in ${RBAC_CONFIG_MAP} on Argo CD at ${host}. Write it as a flow list on one line, such as "[groups, email]".`,
    });
  }
  if (scopes.includes("email")) return;
  throw failedCheck({
    step: "scopes",
    host,
    type: "validation_error",
    message: `${RBAC_CONFIG_MAP} on Argo CD at ${host} doesn't have email in scopes, so Argo CD won't match the lines P0 writes, which name users by email. Add email to scopes, such as "[groups, email]".`,
  });
};

/**
 * `p0_policy`: `policy.p0.csv` is absent, or holds only lines P0 writes,
 * spelled as it writes them, and blank lines. Space around a line is
 * trimmed as Argo CD trims it, as a grant and a revoke do when they look
 * for P0's line, so a CRLF line ending passes. The connector owns the key, so
 * a line someone else put there could be removed by a revoke, or granted
 * from by mistake. The message names each such line by its number, never by
 * what it says.
 */
const requireOnlyP0Lines = (value: string | undefined, host: string) => {
  const foreign = (value ?? "")
    .split("\n")
    .flatMap((text, index) =>
      goTrim(text) === "" || parseP0Line(goTrim(text)) !== undefined
        ? []
        : [index + 1]
    );
  if (foreign.length === 0) return;
  throw failedCheck({
    step: "p0_policy",
    host,
    type: "validation_error",
    message: `${P0_POLICY_KEY} in ${RBAC_CONFIG_MAP} on Argo CD at ${host} has a line P0 didn't write (${foreign.length === 1 ? "line" : "lines"} ${foreign.join(", ")}). The connector owns that key: move the line to another policy key, or remove it.`,
    payload: { lines: foreign.join("; ") },
  });
};

/**
 * The checks on Argo CD, in order, each failing at its step. Every step
 * after `account` relies on the token being the connector's: with anonymous
 * access on, Argo CD would answer the rest for the anonymous user.
 *
 * The empty patch is a real write: argocd-server applies `{"data":{}}` to
 * `argocd-rbac-cm`, which changes nothing but shows in Argo CD's audit log.
 * It proves the fine-grained `update` permission, which `can-i` can't ask
 * about. It comes last, after the self-check, so an account that may do
 * more than it needs never writes.
 */
export const checkArgoCd = async (
  argocd: ArgoCdClient,
  input: Instance,
  host: string
): Promise<Pick<InstallValidation, "argoCdVersion">> => {
  const argoCdVersion = await readVersion(argocd, host);
  requireSupportedVersion(argoCdVersion, host);
  await requireConnectorAccount(argocd, host);
  await requireManagingApp(argocd, input, host);
  const target = rbacTargetOf(input);
  const data = await readRbacData(argocd, target, host);
  const policy = parsePolicy({ data });
  requireEmailScope(policy.scopes, host);
  requireOnlyP0Lines(data[P0_POLICY_KEY], host);
  if (policy.refusedLines.length > 0) {
    throw failedCheck({
      ...policyNotLoaded(host, policy).data,
      step: "policy_loaded",
      host,
    });
  }
  await at("projects", host, () => argocd.listProjects());
  await at("self_check", host, () => assertLeastPrivilege(argocd, host));
  await at("patch", host, () => argocd.patchRbacConfigMap(target, {}));
  return { argoCdVersion };
};

/**
 * Install validation: the connector has a pattern that compiles, can read
 * the instance's token, and Argo CD passes {@link checkArgoCd}. The pattern
 * goes first, before any call leaves the connector, as a grant's does.
 */
const getInstallValidation = async (
  input: Instance,
  logger: Logger
): Promise<InstallValidation> => {
  const host = hostOf(input);
  const allowedEmailDomainPattern = requireAllowedEmailDomainPattern(
    host,
    logger
  );
  // The token stays in this closure and the client's, and is never logged.
  const token = await at("secret", host, () =>
    readApiToken(input.secret, logger)
  );
  // A token that can't go in a header is refused here, before any call.
  const argocd = await at("secret", host, () =>
    argoCdClientFor({ url: input.url, token, logger })
  );
  return {
    ...(await checkArgoCd(argocd, input, host)),
    allowedEmailDomainPattern,
  };
};

/**
 * `install.validation.get`: validates the instance it is given, answering
 * {@link InstallValidation} or throwing the first check's failure.
 */
export const router = (t: AnyConnectorTRPCInstance) => {
  const { router } = t;
  // Logs each validation and its failure, as the access routes do.
  const procedure = withRouteLogging(t.procedure);

  return router({
    get: procedure.input(instance.parse).query(async ({ input, ctx }) => {
      const validation = await getInstallValidation(input, ctx.logger);
      ctx.logger.info(
        { url: input.url, ...validation },
        "validated the Argo CD instance"
      );
      return validation;
    }),
  });
};
