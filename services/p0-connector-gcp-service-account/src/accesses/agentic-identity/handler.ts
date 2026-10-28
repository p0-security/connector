/**
 * Agentic identity lifecycle, as a resource-root connector.
 *
 * P0 mints a short-lived service account per grant so that an AI
 * agent reaching a Google API does so as itself rather than as the human who
 * asked. The "user" of the resource-root contract is that service account; the
 * "policies" are which federated principal may impersonate it, and until when.
 *
 * The GCP-side implementation lives in `@p0security/gcloud-common`, next to
 * the member verifier and policy router it is built from; this service is the
 * transport.
 */
import type {
  AnyConnectorTRPCInstance,
  ResourceRootConnectorPrimitives,
  ResourceRootSchemaOf,
} from "@p0security/connector";
import { newResourceRootRouter } from "@p0security/connector";
import {
  createClients,
  gcloudServiceMetadata,
  newAgenticIdentityPrimitives,
} from "@p0security/gcloud-common";

import { spec } from "./definition.ts";

type ResourceSchema = ResourceRootSchemaOf<typeof spec>;

// Resolved per request rather than at startup: the metadata server is not
// reachable while the module graph is loading.
const connect = async () => ({
  client: await createClients(),
  metadata: await gcloudServiceMetadata(),
});

export const router = (t: AnyConnectorTRPCInstance) =>
  newResourceRootRouter<ResourceSchema>(
    t,
    spec,
    (): ResourceRootConnectorPrimitives<ResourceSchema> =>
      newAgenticIdentityPrimitives(connect)
  );
