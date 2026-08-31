/**
 * The published surface of `@p0security/connector-sdk` (spec.md §5.3,
 * issue 26 §1). This is what P0 must keep compatible forever, so this file
 * exports exactly this list and nothing else generic:
 *
 * - `newResourceRootRouter`, `newZodResourceRootParsers`
 * - `newConnectorTRPC`, `newConnectorRouter`, `newMetadataRouter`
 * - `createLogger`, `ConnectorError`
 * - Two named serving entrypoints: `runCloudRunConnector` (GCP), `newCloudFunction` (AWS Lambda)
 * - Types: `ConnectorPrimitives`, `ResourceRootSchemaOf`, `ConnectorContext`, `Logger`, `SelectItem`
 * - The pre-instantiated schema and parsers for the frozen Custom Application
 *   wire contract, plus the router type the control plane compiles against
 *
 * A customer never imports `buildResourceRootSecurityPerimeter` or a raw,
 * customer-parameterized `ResourceRootSchema` — `newResourceRootRouter`
 * calls the former internally, and this package fixes the latter (spec.md
 * §5.1). Publishing the generic, unfixed form would make every
 * `ResourceRootSchema` type parameter part of the compatibility promise.
 */

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

export {
  connectorParsers,
  ListerQuerySchema,
  ListerResponseSchema,
  PolicySchema,
  RequestContextSchema,
  UserBodySchema,
  UserIdSchema,
} from "./schema.ts";
export type { ConnectorPrimitives, CustomConnectorRouter } from "./schema.ts";
