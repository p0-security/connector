import {
  newConnectorRouter,
  newConnectorTRPC,
  newMetadataRouter,
} from "@p0security/connector-core";

import gcpServiceAccountConnectorPackageJson from "../package.json" with { type: "json" };
import { router as agenticIdentityRouter } from "./accesses/agentic-identity/handler.ts";

export const t = newConnectorTRPC();
export const router = t.router;
export const baseProcedure = t.procedure;

// The install's own work — this service's identity, and the custom role that
// lets it mint service accounts — is customer-applied terraform.
const installRouter = router({});

export const connectorRouter = newConnectorRouter(
  "gcp-service-account" as const,
  t,
  { agenticIdentity: agenticIdentityRouter(t) },
  installRouter,
  newMetadataRouter(
    t,
    gcpServiceAccountConnectorPackageJson.version ?? "unknown"
  )
);
