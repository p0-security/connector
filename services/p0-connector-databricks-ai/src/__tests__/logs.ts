import type * as Connector from "@p0security/connector-core";
import { inspect } from "node:util";

/**
 * Every line any logger the connector creates writes, at every level, with
 * its arguments rendered in full (errors with their causes and payloads). A
 * suite that needs it mocks `@p0security/connector` with
 * {@link recordingLoggerModule}:
 *
 * ```ts
 * vi.mock("@p0security/connector-core", async (importOriginal) =>
 *   (await import("./logs.ts")).recordingLoggerModule(importOriginal)
 * );
 * ```
 *
 * Like `sts.ts`, this file imports nothing that loads the module it mocks.
 */
export const logLines: string[] = [];

const LEVELS = ["trace", "debug", "info", "warn", "error", "fatal"] as const;

/**
 * The real framework, except that `createLogger` returns one logger that
 * records every line in {@link logLines}, and whose children are itself.
 */
export const recordingLoggerModule = async (
  importOriginal: () => Promise<typeof Connector>
): Promise<Record<string, unknown>> => {
  const logger: Record<string, unknown> = { level: "trace" };
  for (const level of LEVELS) {
    logger[level] = (...args: unknown[]) => {
      logLines.push(`${level} ${inspect(args, { depth: null })}`);
    };
  }
  logger.child = (bindings: unknown) => {
    logLines.push(`child ${inspect(bindings, { depth: null })}`);
    return logger;
  };
  return { ...(await importOriginal()), createLogger: () => logger };
};
