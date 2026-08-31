import {
  type ConnectorContext,
  newConnectorRouter,
  newConnectorTRPC,
  newResourceRootRouter,
} from "@p0security/connector-core";

import { newMetadataRouter } from "./metadata.ts";
import { type ConnectorPrimitives, connectorParsers } from "./schema.ts";

export const newCustomConnectorRouter = (params: {
  primitives:
    ConnectorPrimitives | ((ctx: ConnectorContext) => ConnectorPrimitives);
  connectorVersion: string;
}) => {
  const t = newConnectorTRPC();
  const getPrimitives =
    typeof params.primitives === "function"
      ? params.primitives
      : () => params.primitives as ConnectorPrimitives;

  return newConnectorRouter(
    "app",
    t,
    { access: newResourceRootRouter(t, connectorParsers, getPrimitives) },
    t.router({}),
    newMetadataRouter(t, params.connectorVersion)
  );
};

export type CustomConnectorRouter = ReturnType<typeof newCustomConnectorRouter>;
