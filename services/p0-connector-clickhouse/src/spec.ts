import { spec as consoleSpec } from "./accesses/console/definition.ts";
import { spec as sqlSpec } from "./accesses/sql/definition.ts";

export const connectorSpec = {
  sql: sqlSpec,
  console: consoleSpec,
};
