import {
  newConnectorRouter,
  newConnectorTRPC,
  newMetadataRouter,
} from "@p0security/connector-core";

import cloudsqlConnectorPackageJson from "../package.json" with { type: "json" };
import { router as userRouter } from "./accesses/user/handler.ts";

export const t = newConnectorTRPC();
export const router = t.router;
export const baseProcedure = t.procedure;

// No-op install router: the CloudSQL connector provisions IAM database users and
// has no install-time validation to run (unlike the mysql/pg DB-connection check).
// the install is IAM grant check that p0 backend is already granted via IAM management.
const installRouter = router({});

export const connectorRouter = newConnectorRouter(
  "cloudsql" as const,
  t,
  { user: userRouter(t) },
  installRouter,
  newMetadataRouter(t, cloudsqlConnectorPackageJson.version ?? "unknown")
);
