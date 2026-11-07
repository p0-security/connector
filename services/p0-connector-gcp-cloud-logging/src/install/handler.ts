import {
  type AnyConnectorTRPCInstance,
  ConnectorError,
  type Logger,
  withRouteLogging,
} from "@p0security/connector-core";

import {
  type LoggingDependencies,
  assertProjectId,
  auditLogName,
  filterString,
  newLogging,
  toConnectorError,
} from "../logging.ts";
import {
  type InstallInput,
  type InstallValidation,
  installInput,
} from "./definition.ts";

const DAY_MS = 86_400_000;

/**
 * Lists one Data Access entry from the last day. Private logs need
 * `logging.privateLogEntries.list`, so this fails without
 * `roles/logging.privateLogViewer` even when the project has no entries.
 */
export const validateInstall = async (
  input: InstallInput,
  logger: Logger,
  dependencies: LoggingDependencies = {}
): Promise<InstallValidation> => {
  const logging = newLogging(dependencies);
  const projectId = assertProjectId(input.projectId);
  const since = new Date(logging.now() - DAY_MS).toISOString();
  try {
    await logging.listEntries({
      resourceNames: [`projects/${projectId}`],
      filter: `logName=${filterString(auditLogName(projectId, "data_access"))}\ntimestamp>=${filterString(since)}`,
      orderBy: "timestamp desc",
      pageSize: 1,
    });
  } catch (error) {
    const { data } = toConnectorError(error);
    throw new ConnectorError({
      ...data,
      message: `The connector can't read Cloud Audit Logs in ${projectId}: ${data.message}`,
      payload: { ...data.payload, step: "read_logs", projectId },
    });
  }
  logger.info({ projectId }, "validated the Cloud Logging install");
  return { projectId, warnings: [] };
};

/** Lets the installer confirm the connector can read the project's logs. */
export const router = (
  t: AnyConnectorTRPCInstance,
  dependencies: LoggingDependencies = {}
) => {
  const procedure = withRouteLogging(t.procedure);
  return t.router({
    get: procedure
      .input(installInput.parse)
      .query(({ input, ctx }): Promise<InstallValidation> =>
        validateInstall(input, ctx.logger, dependencies)
      ),
  });
};
