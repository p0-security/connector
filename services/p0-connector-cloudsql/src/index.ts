import { connectorRouter } from "./router.ts";
import { connectorSpec } from "./spec.ts";

export const cloudSqlConnectorRouter = connectorRouter;
export const CloudSqlConnectorSpec = connectorSpec;

export type CloudSqlConnectorRouter = typeof connectorRouter;
export type CloudSqlConnectorSpec = typeof connectorSpec;
