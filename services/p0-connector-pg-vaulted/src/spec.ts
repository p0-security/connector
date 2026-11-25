import { spec as roleSpec } from "./accesses/role/definition.ts";
import { spec as sqlSpec } from "./accesses/sql/definition.ts";

export const connectorSpec = {
  role: roleSpec,
  sql: sqlSpec,
};
