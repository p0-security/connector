import type { z } from "zod";

import { ConnectorError } from "../errors/index.ts";
import { withRouteLogging } from "../security-perimeters/common/middleware.ts";
import type {
  AnyConnectorTRPCInstance,
  ConnectorContext,
} from "../security-perimeters/common/trpc.ts";
import {
  type LogCheckInput,
  LogCheckInputSchema,
  type LogCheckResult,
  LogCheckResultSchema,
  type LogReadInput,
  LogReadInputSchema,
  type LogReadResult,
  LogReadResultSchema,
} from "./schema.ts";

/** What a log-source connector implements behind its `logs` route. */
export type LogSourceHandlers = {
  /** Reads one page of entries for a query, or polls a running one. */
  read: (input: LogReadInput, ctx: ConnectorContext) => Promise<LogReadResult>;
  /** The read-time setup checks the connector can make in its own account or project. */
  check: (
    input: LogCheckInput,
    ctx: ConnectorContext
  ) => Promise<LogCheckResult>;
};

/**
 * tRPC's own input validation answers a bad input with a bare `BAD_REQUEST`.
 * The contract promises a `validation_error`, so the procedures take their
 * input unparsed (typed for the client) and parse it here.
 */
const parseOrValidationError = <Schema extends z.ZodType>(
  schema: Schema,
  raw: unknown
): z.infer<Schema> => {
  const result = schema.safeParse(raw);
  if (result.success) return result.data;
  throw new ConnectorError({
    type: "validation_error",
    message: `Invalid logs input: ${result.error.message}`,
    payload: {},
    cause: result.error,
  });
};

/** Types the raw input for the client without validating it (see {@link parseOrValidationError}). */
const unparsed =
  <Input>() =>
  (raw: unknown) =>
    raw as Input;

/**
 * Builds the `logs` router a log-source connector passes as the sixth
 * argument of {@link newConnectorRouter}, exposing `{ns}.logs.read` and
 * `{ns}.logs.check`.
 *
 * Inputs that fall outside the closed {@link LogQuery} union are rejected
 * with a `validation_error` before a handler runs. Outputs are validated too;
 * the control plane re-validates them with the same schemas.
 *
 * Both are mutations, not queries, so their input travels in the request
 * body: a GCP role's permission list can run to thousands of entries, too
 * long for a URL.
 *
 * @summary Builds the `logs` router of a log-source connector.
 * @category High-Level
 */
export const newLogsRouter = <
  TRPCInstance extends AnyConnectorTRPCInstance = AnyConnectorTRPCInstance,
>(
  t: TRPCInstance,
  handlers: LogSourceHandlers
) => {
  const procedure = withRouteLogging(t.procedure);
  return t.router({
    read: procedure
      .input(unparsed<LogReadInput>())
      .output(LogReadResultSchema)
      .mutation(({ input, ctx }) =>
        handlers.read(parseOrValidationError(LogReadInputSchema, input), ctx)
      ),
    check: procedure
      .input(unparsed<LogCheckInput>())
      .output(LogCheckResultSchema)
      .mutation(({ input, ctx }) =>
        handlers.check(parseOrValidationError(LogCheckInputSchema, input), ctx)
      ),
  });
};

export type LogsRouter = ReturnType<typeof newLogsRouter>;
