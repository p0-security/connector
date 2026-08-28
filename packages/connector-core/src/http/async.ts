import type { NextFunction, Request, RequestHandler, Response } from "express";

export type AsyncRequestHandler<
  PathParams = object,
  ResBody = any,
  ReqBody = any,
  ReqQuery = object,
  Locals extends Record<string, any> = Record<string, never>,
> = (
  req: Request<PathParams, ResBody, ReqBody, ReqQuery, Locals>,
  res: Response<ResBody, Locals>,
  next: NextFunction
) => Promise<void>;

/**
 * Wraps an async request handler to catch any unhandled exceptions and pass them to the
 * Express error handler. This is useful for handling async functions in Express routes.
 */
export const asyncRequestHandler =
  <
    PathParams = object,
    ResBody = any,
    ReqBody = any,
    ReqQuery = object,
    Locals extends Record<string, any> = Record<string, never>,
  >(
    handler: AsyncRequestHandler<PathParams, ResBody, ReqBody, ReqQuery, Locals>
  ): RequestHandler<PathParams, ResBody, ReqBody, ReqQuery, Locals> =>
  (req, res, next) => {
    handler(req, res, next).catch(next);
  };
