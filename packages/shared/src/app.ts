import type { Router } from "express";
import express from "express";

import { errorHandler } from "./error-handler.ts";

export const runExpressApp = (
  moduleName: string,
  routes: Record<string, Router>,
  middlewares: express.RequestHandler[] = []
) => {
  const app = express();
  app.use(express.json());

  app.get("/health", (_req, res) =>
    res.json({ status: "UP", module: moduleName })
  );

  for (const middleware of middlewares) {
    app.use(middleware);
  }

  for (const [path, router] of Object.entries(routes)) {
    app.use(path, router);
  }

  app.use(errorHandler);

  const PORT = process.env.PORT || 8080;
  app.listen(PORT, () => {
    // eslint-disable-next-line no-console -- startup log for server boot
    console.log(`Server is running on port ${PORT}`);
  });
};
