import { spec as forceMergeSpec } from "./accesses/force-merge/definition.ts";
import { spec as roleSpec } from "./accesses/role/definition.ts";
import { spec as teamSpec } from "./accesses/team/definition.ts";

export const connectorSpec = {
  role: roleSpec,
  team: teamSpec,
  "force-merge": forceMergeSpec,
};
