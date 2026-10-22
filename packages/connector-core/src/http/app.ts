import type { Router } from "express";
import express from "express";

import { createLogger } from "../logger.ts";
import { errorHandler } from "./error-handler.ts";

const logger = createLogger();

/**
 * Builds the Express app without binding a port.
 *
 * `GET /health` is mounted ahead of `middlewares`, so a load balancer can probe
 * it without a token. Every other path, including an unknown one, passes
 * through `middlewares` first.
 */
export const createExpressApp = (
  moduleName: string,
  routes: Record<string, Router>,
  middlewares: express.RequestHandler[] = []
) => {
  const app = express();

  app.get("/health", (_req, res) => {
    res.status(200).json({ module: moduleName });
  });

  app.use(express.json());

  for (const middleware of middlewares) {
    app.use(middleware);
  }

  for (const [path, router] of Object.entries(routes)) {
    app.use(path, router);
  }

  app.use(errorHandler);

  return app;
};

export const runExpressApp = (
  moduleName: string,
  routes: Record<string, Router>,
  middlewares: express.RequestHandler[] = []
) => {
  const app = createExpressApp(moduleName, routes, middlewares);

  const PORT = process.env.PORT || 8080;
  app.listen(PORT, () => {
    logger.info({ port: PORT, module: moduleName }, "Server is running");
  });
};
