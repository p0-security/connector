import { spec as adminSpec } from "./accesses/admin/definition.ts";
import { spec as privilegeSpec } from "./accesses/privilege/definition.ts";

export const connectorSpec = { privilege: privilegeSpec, admin: adminSpec };
