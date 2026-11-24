import {
  newConnectorRouter,
  newConnectorTRPC,
  newMetadataRouter,
} from "@p0security/connector-core";

import pgVaultedConnectorPackageJson from "../package.json" with { type: "json" };

export const t = newConnectorTRPC();
export const router = t.router;
export const baseProcedure = t.procedure;

export const connectorRouter = newConnectorRouter("pg-vaulted" as const, t, {
  accesses: {},
  install: router({}),
  metadata: newMetadataRouter(
    t,
    pgVaultedConnectorPackageJson.version ?? "unknown"
  ),
});
