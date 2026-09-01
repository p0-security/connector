import { CUSTOM_APP_ACCESS } from "./constants.ts";
import { connectorParsers } from "./schema.ts";

export const CustomAppConnectorSpec = {
  [CUSTOM_APP_ACCESS]: connectorParsers,
};

export type CustomAppConnectorSpec = typeof CustomAppConnectorSpec;
