import { ConnectorError, type Logger } from "@p0security/connector-core";

/** An SDK command as a fake AWS client gets it: its class and its input. */
export type Command = {
  constructor: { name: string };
  input: Record<string, unknown>;
};

/** An SDK failure, which the SDK names by `name`. */
export const sdkError = (name: string, message = name) =>
  Object.assign(new Error(message), { name });

/**
 * A logger that keeps every line, and the bindings of every child, to check
 * what the code never logs.
 */
export const recordingLogger = () => {
  const lines: unknown[][] = [];
  const record = (...line: unknown[]) => {
    lines.push(line);
  };
  // A pino logger has many more members, and the code calls only these.
  const logger = {
    debug: record,
    info: record,
    warn: record,
    error: record,
    child: (bindings: unknown) => {
      lines.push([bindings]);
      return logger;
    },
  } as unknown as Logger;
  return { logger, lines };
};

const errorOf = async (promise: Promise<unknown>) => {
  const error = await promise.catch((e: unknown) => e);
  if (!(error instanceof Error)) {
    throw new Error(`expected an Error, got ${String(error)}`);
  }
  return error;
};

/** The connector error a call threw, which tRPC can wrap. */
const connectorErrorOf = (error: Error) => {
  if (error instanceof ConnectorError) return error;
  if (error.cause instanceof ConnectorError) return error.cause;
  throw new Error(`expected a ConnectorError, got ${String(error)}`);
};

/** The data of the connector error a call rejected with. */
export const dataOf = async (promise: Promise<unknown>) =>
  connectorErrorOf(await errorOf(promise)).data;
