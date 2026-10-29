import { spec as objectsSpec } from "./accesses/objects/definition.ts";
import { spec as roleSpec } from "./accesses/role/definition.ts";

export const connectorSpec = {
  role: roleSpec,
  objects: objectsSpec,
};
