import {
  newConnectorRouter,
  newConnectorTRPC,
  newMetadataRouter,
} from "@p0security/connector";

import jiraAiConnectorPackageJson from "../package.json" with { type: "json" };
import { router as roleRouter } from "./accesses/role/handler.ts";
import { router as tokenRouter } from "./accesses/token/handler.ts";
import { accountRouter, projectRouter, siteRouter } from "./install/handler.ts";

export const t = newConnectorTRPC();

const installRouter = t.router({
  site: siteRouter(t),
  account: accountRouter(t),
  project: projectRouter(t),
});

export const connectorRouter = newConnectorRouter(
  "jira-ai" as const,
  t,
  { role: roleRouter(t), token: tokenRouter(t) },
  installRouter,
  newMetadataRouter(t, jiraAiConnectorPackageJson.version ?? "unknown")
);
