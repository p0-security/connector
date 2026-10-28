import {
  newConnectorRouter,
  newConnectorTRPC,
  newMetadataRouter,
} from "@p0security/connector-core";

import auth0ConnectorPackageJson from "../package.json" with { type: "json" };
import { router as organizationRouter } from "./accesses/organization/handler.ts";
import { router as permissionRouter } from "./accesses/permission/handler.ts";
import { router as roleRouter } from "./accesses/role/handler.ts";
import { router as validationRouter } from "./install/handler.ts";

export const t = newConnectorTRPC();

const installRouter = t.router({ validation: validationRouter(t) });

export const connectorRouter = newConnectorRouter(
  "auth0" as const,
  t,
  {
    role: roleRouter(t),
    permission: permissionRouter(t),
    organization: organizationRouter(t),
  },
  installRouter,
  newMetadataRouter(t, auth0ConnectorPackageJson.version ?? "unknown")
);
