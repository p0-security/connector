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

export const errorHandler: ErrorRequestHandler = (error, _req, res, _next) => {
  logger.error({ error }, "Error processing request");

  let status;
  switch (error.type) {
    case "auth":
      status = 403;
      break;
    // TODO: Identify and handle upstream errors
    default:
      status = 500;
  }

  const serializedError = serializeError(error);
  return res.status(status).json({ error: serializedError });
};
