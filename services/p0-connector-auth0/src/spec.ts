import { spec as organizationSpec } from "./accesses/organization/definition.ts";
import { spec as permissionSpec } from "./accesses/permission/definition.ts";
import { spec as roleSpec } from "./accesses/role/definition.ts";

export const connectorSpec = {
  role: roleSpec,
  permission: permissionSpec,
  organization: organizationSpec,
};
