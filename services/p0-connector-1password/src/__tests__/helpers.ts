import { ConnectorError, createLogger } from "@p0security/connector";
import { vi } from "vitest";

/** What `run` threw, for a test that looks at more than its message. */
export const thrown = async (run: () => Promise<unknown>): Promise<unknown> => {
  try {
    await run();
  } catch (error) {
    return error;
  }
  throw new Error("expected the call to throw");
};

/** What P0 gets when `run` fails: the connector error's type, message and payload. */
export const connectorError = async (run: () => Promise<unknown>) => {
  const error = await thrown(run);
  if (error instanceof ConnectorError) return error.data;
  throw error;
};

/**
 * A silent logger whose child loggers are itself, so a test can read what any
 * of them logged.
 */
export const newRecordingLogger = () => {
  const log = createLogger();
  log.level = "silent";
  vi.spyOn(log, "child").mockReturnValue(log);
  return {
    log,
    info: vi.spyOn(log, "info"),
    warn: vi.spyOn(log, "warn"),
    error: vi.spyOn(log, "error"),
  };
};
