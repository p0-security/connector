import type { RequestHandler } from "express";

import { asyncRequestHandler } from "../async.ts";
import { AuthError } from "../types/error.ts";

export const bearerAuthzMiddleware = (
  handler: (token: string) => Promise<boolean>
): RequestHandler =>
  asyncRequestHandler(async (req, _res, next) => {
    if (!req.headers.authorization) {
      throw new AuthError("Unauthorized");
    }
    const [authenticationType, token] = req.headers.authorization.split(" ");
    if (!authenticationType || !token) {
      throw new AuthError("Unauthorized");
    }

    if (authenticationType.toLowerCase() !== "bearer") {
      throw new AuthError("Unauthorized");
    }

    try {
      if (!(await handler(token))) {
        throw new AuthError("Unauthorized");
      }
    } catch (err) {
      throw new AuthError("Unauthorized", err);
    }
    next();
  });
