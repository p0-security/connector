import {
  type AnyConnectorTRPCInstance,
  ConnectorError,
  type ConnectorErrorOptions,
  type Logger,
  withRouteLogging,
} from "@p0security/connector";

import { requireAllowedDomains } from "../allowed-domains.ts";
import {
  type CloudClient,
  type Service,
  newCloudClient,
} from "../cloud/client.ts";
import {
  isForbidden,
  isKeyRejected,
  isOtherOrganization,
  toConnectorError,
} from "../cloud/errors.ts";
import {
  REQUIRED_PERMISSIONS,
  type RequiredPermission,
} from "../cloud/permissions.ts";
import type { OrganizationCredentials } from "../credentials.ts";
import {
  type InstallValidation,
  type ServiceReport,
  installInput,
} from "./definition.ts";

/** The checks, by the name a failure reports in `payload.step`. They run as spec section 3 orders them. */
type Step = "authenticate" | "domains" | "permissions" | "secret" | "services";

/**
 * The error for a failed check. The answer carries facts, not results, so a
 * failure is thrown, and `payload.step` is how P0 tells one from another.
 * `payload.organizationId` says which organization was being validated.
 */
const failedCheck = ({
  step,
  organizationId,
  type,
  message,
  payload,
}: Pick<ConnectorErrorOptions, "message" | "type"> &
  Partial<Pick<ConnectorErrorOptions, "payload">> & {
    organizationId: string;
    step: Step;
  }) =>
  new ConnectorError({
    type,
    message,
    payload: { ...payload, step, organizationId },
  });

/** Runs one check, naming its step on whatever it fails with. */
const runStep = async <T>(
  step: Step,
  organizationId: string,
  check: () => Promise<T>
): Promise<T> => {
  try {
    return await check();
  } catch (error) {
    const mapped = toConnectorError(error, { organizationId });
    throw mapped instanceof ConnectorError
      ? failedCheck({ ...mapped.data, step, organizationId })
      : mapped;
  }
};

/** `secret`: the connector can read and parse the API key. */
const checkSecret = (cloud: CloudClient, organizationId: string) =>
  runStep("secret", organizationId, () => cloud.readKey());

/** `authenticate`: the organization answers to the key, with its name. */
const authenticate = (cloud: CloudClient, organizationId: string) =>
  runStep("authenticate", organizationId, async () => {
    try {
      return (await cloud.getOrganization()).name;
    } catch (error) {
      if (isKeyRejected(error)) {
        throw failedCheck({
          step: "authenticate",
          organizationId,
          type: "insufficient_privileges",
          message: `The ClickHouse Cloud organization ${organizationId} rejected P0's API key (401): the key ID or secret is wrong, or the key is disabled or expired. Check the key in its secret.`,
          payload: { status: error.status },
        });
      }
      if (isOtherOrganization(error)) {
        throw failedCheck({
          step: "authenticate",
          organizationId,
          type: "insufficient_privileges",
          message: `The ClickHouse Cloud organization ${organizationId} didn't answer to P0's API key (${error.status}): the key belongs to another organization, or its p0-connector role lacks control-plane:organization:view. Check the key's role and the organization ID. If the ID is wrong, remove the organization in P0 and add it again.`,
          payload: { status: error.status },
        });
      }
      throw error;
    }
  });

/**
 * A probe's answer: whether the key has the permission. Only a 403 says it
 * doesn't. Any other failure fails the step as it is.
 */
const probe = async (call: () => Promise<unknown>): Promise<boolean> => {
  try {
    await call();
    return true;
  } catch (error) {
    if (isForbidden(error)) return false;
    throw error;
  }
};

/**
 * The service the permission probes read: the first that isn't BYOC, or the
 * first of all when every one is.
 */
const probeTarget = (services: Service[]): Service | undefined =>
  services.find(({ byocId }) => !byocId) ?? services[0];

/**
 * `permissions`: one probe per permission the key's role must hold, naming
 * every one that's missing, `organization:view-api-keys` last.
 * `service:manage-query-api-endpoints` has no probe that changes nothing,
 * so it's first used, and a 403 names it, when a lookup sets up P0's
 * endpoints on a service. With no services, the two service probes are
 * skipped, and `services` fails.
 * Extra permissions are ignored.
 */
const checkPermissions = (
  cloud: CloudClient,
  organizationId: string
): Promise<Service[]> =>
  runStep("permissions", organizationId, async () => {
    // Listing the services needs no permission beyond a valid key.
    const services = await cloud.listServices();
    const target = probeTarget(services);
    const probes: [RequiredPermission, () => Promise<unknown>][] = [
      ["control-plane:organization:view", () => cloud.listMembers()],
      ["control-plane:organization:manage", () => cloud.listRoles()],
      ...(target === undefined
        ? []
        : ([
            ["control-plane:service:view", () => cloud.getService(target.id)],
            [
              "control-plane:service:view-query-api-endpoints",
              () => cloud.listEndpoints(target.id),
            ],
          ] satisfies [RequiredPermission, () => Promise<unknown>][])),
      ["control-plane:organization:view-api-keys", () => cloud.listKeys()],
    ];
    // One probe at a time, so one that fails other than with a 403 stops the
    // rest.
    const missing = await probes.reduce<Promise<RequiredPermission[]>>(
      async (before, [permission, call]) => {
        const earlier = await before;
        return (await probe(call)) ? earlier : [...earlier, permission];
      },
      Promise.resolve([])
    );
    if (missing.length > 0) {
      throw failedCheck({
        step: "permissions",
        organizationId,
        type: "insufficient_privileges",
        message: `P0's API key for the ClickHouse Cloud organization ${organizationId} is missing ${
          missing.length === 1 ? "a permission" : "permissions"
        }: ${missing.join(", ")}. Add ${
          missing.length === 1 ? "it" : "them"
        } to the key's p0-connector role, which needs ${REQUIRED_PERMISSIONS.join(", ")}, then try again.`,
        payload: { missing: missing.join(" ") },
      });
    }
    return services;
  });

/** The oldest ClickHouse whose SQL console takes a custom role's grants. */
const MIN_VERSION = [26, 4] as const;

/** A service's ClickHouse version as `[major, minor]`, or `undefined` when it can't be read. */
const versionOf = (version: string | undefined) => {
  const match = /^(\d+)\.(\d+)(?:\.|$)/.exec(version ?? "");
  return match ? [Number(match[1]), Number(match[2])] : undefined;
};

const isSupported = ([major = 0, minor = 0]: number[]) =>
  major > MIN_VERSION[0] ||
  (major === MIN_VERSION[0] && minor >= MIN_VERSION[1]);

/**
 * Where one service stands, from the organization's service listing alone:
 * BYOC isn't supported; one older than 26.4, or whose version ClickHouse
 * Cloud doesn't report, is console-only; any other is ready. The install
 * makes no call about a service: P0 sets up its endpoints on a service the
 * first time a lookup needs them there.
 */
const reportService = ({
  id,
  name,
  byocId,
  clickhouseVersion,
}: Service): ServiceReport => {
  if (byocId) {
    return { id, name, status: "not-ready", reason: "BYOC isn't supported" };
  }
  const version = versionOf(clickhouseVersion);
  if (version === undefined) {
    return {
      id,
      name,
      status: "console-only",
      reason:
        "ClickHouse Cloud didn't report the service's ClickHouse version, so only console access can be requested",
    };
  }
  if (!isSupported(version)) {
    return {
      id,
      name,
      status: "console-only",
      reason: `ClickHouse ${clickhouseVersion} is older than 26.4, so only console access can be requested`,
    };
  }
  return { id, name, status: "ready" };
};

// Only for services that aren't ready, so the status goes without saying.
const summary = (report: ServiceReport): string =>
  "reason" in report ? `${report.name}: ${report.reason}` : report.name;

/**
 * `services`: first the key's UUID, which P0's endpoints' `apiKeyIds` take,
 * is found among the organization's keys. Then every service gets a report
 * ({@link reportService}) from the listing the `permissions` step read,
 * with no call about any one service. The step fails when the key can't be
 * identified, and when every service is `not-ready` (a `console-only` one
 * still takes console role requests), with each in its message and their
 * IDs in `payload.notReady`. The reports keep the services' order.
 */
const checkServices = ({
  cloud,
  organizationId,
  organizationName,
  services,
  log,
}: {
  cloud: CloudClient;
  organizationId: string;
  organizationName: string;
  services: Service[];
  log: Logger;
}): Promise<{ apiKeyUuid: string; reports: ServiceReport[] }> =>
  runStep("services", organizationId, async () => {
    const apiKeyUuid = await cloud.keyUuid();
    if (services.length === 0) {
      throw failedCheck({
        step: "services",
        organizationId,
        type: "dependency_violation",
        message: `The ClickHouse Cloud organization ${organizationName} has no services. Create one, then try again.`,
      });
    }
    const reports = services.map(reportService);
    for (const report of reports) log.info(report, "checked a service");
    // A console-only service still takes console role requests.
    if (reports.every(({ status }) => status === "not-ready")) {
      throw failedCheck({
        step: "services",
        organizationId,
        type: "dependency_violation",
        message: `No service in the ClickHouse Cloud organization ${organizationName} can take requests from P0. ${reports
          .map(summary)
          .join(". ")}.`,
        payload: { notReady: reports.map(({ id }) => id).join(",") },
      });
    }
    return { apiKeyUuid, reports };
  });

/** `domains`: the connector has a usable `DOMAIN_ALLOW_PATTERN`, which it reports. */
const checkDomains = (organizationId: string, logger: Logger): string => {
  try {
    return requireAllowedDomains().pattern;
  } catch (error) {
    // The message names the variable and why. It never holds a secret.
    logger.warn({ error }, "the allowed domains are unusable");
    throw failedCheck({
      step: "domains",
      organizationId,
      type: "validation_error",
      message: error instanceof Error ? error.message : String(error),
    });
  }
};

export const getInstallValidation = async (
  credentials: OrganizationCredentials,
  logger: Logger
): Promise<InstallValidation> => {
  const { organizationId } = credentials;
  const cloud = newCloudClient({ ...credentials, log: logger });
  const { keyId } = await checkSecret(cloud, organizationId);
  const organizationName = await authenticate(cloud, organizationId);
  const services = await checkPermissions(cloud, organizationId);
  const { apiKeyUuid, reports } = await checkServices({
    cloud,
    organizationId,
    organizationName,
    services,
    log: logger,
  });
  const allowedDomains = checkDomains(organizationId, logger);
  return {
    organizationName,
    apiKeyId: keyId,
    apiKeyUuid,
    allowedDomains,
    services: reports,
  };
};

export const router = (t: AnyConnectorTRPCInstance) => {
  const { router } = t;
  // Logs each validation and its failure, as the access routes do.
  const procedure = withRouteLogging(t.procedure);

  return router({
    get: procedure.input(installInput.parse).query(async ({ input, ctx }) => {
      const logger = ctx.logger.child({
        organizationId: input.organizationId,
      });
      const validation = await getInstallValidation(input, logger);
      logger.info(validation, "validated the ClickHouse Cloud organization");
      return validation;
    }),
  });
};
