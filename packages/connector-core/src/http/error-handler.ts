import type { ErrorRequestHandler } from "express";
import { pino } from "pino";

import { BaseError } from "./types/error.ts";

const logger = pino({
  level: process.env.LOG_LEVEL || "info",
});

const serializeError = (error: unknown) => {
  if (error instanceof BaseError) {
    return error.toJSON();
  } else if (error instanceof Error) {
    return {
      name: error.name,
      message: error.message,
      stack: error.stack,
    };
  } else {
    return { message: String(error) };
  }
};

/**
 * The 4xx status of an error Express's own middleware raised about the
 * request, such as body-parser's 413 for a body over the limit, so the
 * caller learns what was wrong with its request rather than seeing a 500.
 */
const clientErrorStatus = (error: unknown) => {
  const { status, expose } = (error ?? {}) as {
    status?: unknown;
    expose?: unknown;
  };
  return expose === true &&
    typeof status === "number" &&
    status >= 400 &&
    status < 500
    ? status
    : undefined;
};

export const errorHandler: ErrorRequestHandler = (error, _req, res, _next) => {
  logger.error({ error }, "Error processing request");

  let status;
  switch (error.type) {
    case "auth":
      status = 403;
      break;
    // TODO: Identify and handle upstream errors
    default:
      status = clientErrorStatus(error) ?? 500;
  }

  const serializedError = serializeError(error);
  return res.status(status).json({ error: serializedError });
};
