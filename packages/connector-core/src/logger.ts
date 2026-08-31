import { pino } from "pino";

export type Logger = ReturnType<typeof pino>;

// Field paths (fast-redact syntax) censored before a log line is serialized,
// regardless of which service or module emitted it
const REDACTED_PATHS = [
  "token",
  "*.token",
  "*.auth.token",
  "privateKey",
  "*.privateKey",
  "password",
  "*.password",
];

/**
 * Builds a pino logger carrying `bindings` on every line it (or any `.child()`
 * of it) emits
 */
export const createLogger = (bindings: Record<string, unknown> = {}): Logger =>
  pino({
    level: process.env.LOG_LEVEL || "info",
    redact: REDACTED_PATHS,
  }).child(bindings);
