import type * as Connector from "@p0security/connector";
import { vi } from "vitest";

/**
 * The `warn` of every logger the connector creates, so a suite can count
 * warnings. A suite that needs it mocks `@p0security/connector` with
 * {@link recordingLoggerModule}:
 *
 * ```ts
 * vi.mock("@p0security/connector", async (importOriginal) =>
 *   (await import("../../../__tests__/logs.ts")).recordingLoggerModule(
 *     importOriginal
 *   )
 * );
 * ```
 *
 * Like `sts.ts`, this file imports nothing that loads the module it mocks.
 */
export const warn = vi.fn();

const ignore = () => {};

/**
 * The real framework, except that `createLogger` returns one silent logger
 * whose children are itself and whose `warn` is {@link warn}.
 */
export const recordingLoggerModule = async (
  importOriginal: () => Promise<typeof Connector>
): Promise<Record<string, unknown>> => {
  const logger: Record<string, unknown> = {
    level: "silent",
    trace: ignore,
    debug: ignore,
    info: ignore,
    warn,
    error: ignore,
    fatal: ignore,
  };
  logger.child = () => logger;
  return { ...(await importOriginal()), createLogger: () => logger };
};

/** How many warnings were about domain verification. */
export const domainWarnings = () =>
  warn.mock.calls.filter(
    ([, message]) =>
      typeof message === "string" && message.includes("domain verification")
  ).length;
