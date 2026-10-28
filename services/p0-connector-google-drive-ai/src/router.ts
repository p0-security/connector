import {
  newConnectorRouter,
  newConnectorTRPC,
  newMetadataRouter,
} from "@p0security/connector-core";

import googleDriveAiConnectorPackageJson from "../package.json" with { type: "json" };
import { router as resourceRouter } from "./accesses/resource/handler.ts";

export const t = newConnectorTRPC();
export const router = t.router;
export const baseProcedure = t.procedure;

// The install's own work — making this connector's service identity an
// organizer on each registered shared drive — is a human step, by design: it
// needs a Workspace privilege P0 is not willing to hold.
const installRouter = router({});

export const connectorRouter = newConnectorRouter(
  "google-drive-ai" as const,
  t,
  { resource: resourceRouter(t) },
  installRouter,
  newMetadataRouter(t, googleDriveAiConnectorPackageJson.version ?? "unknown")
);
