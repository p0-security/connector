import type { Router } from "express";
import express from "express";

import { createLogger } from "../logger.ts";
import { errorHandler } from "./error-handler.ts";

const logger = createLogger();

export const runExpressApp = (
  moduleName: string,
  routes: Record<string, Router>,
  middlewares: express.RequestHandler[] = []
) => {
  const app = express();
  app.use(express.json());

  for (const middleware of middlewares) {
    app.use(middleware);
  }

  for (const [path, router] of Object.entries(routes)) {
    app.use(path, router);
  }

  app.use(errorHandler);

  const PORT = process.env.PORT || 8080;
  app.listen(PORT, () => {
    logger.info({ port: PORT, module: moduleName }, "Server is running");
  });
};
