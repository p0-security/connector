export {
  ConnectorError,
  createLogger,
  newConnectorRouter,
  newConnectorTRPC,
  newCloudFunction,
  newResourceRootRouter,
  newZodResourceRootParsers,
  runCloudRunConnector,
} from "@p0security/connector-core";
export type {
  ConnectorContext,
  Logger,
  ResourceRootSchemaOf,
  SelectItem,
} from "@p0security/connector-core";

export { newMetadataRouter } from "./metadata.ts";

export { newCustomConnectorRouter } from "./router.ts";
export type { CustomConnectorRouter } from "./router.ts";

export {
  connectorParsers,
  ListerQuerySchema,
  ListerResponseSchema,
  PolicySchema,
  RequestContextSchema,
  UserBodySchema,
  UserIdSchema,
} from "./schema.ts";
export type { AccessRouter, ConnectorPrimitives } from "./schema.ts";
