import type { AnyConnectorTRPCInstance } from "@p0security/connector";

import { quoteIdentifier } from "../../sql.ts";
import { type GrantPolicy, newAgentAccessRouter } from "../router.ts";
import { type RolePolicy, spec } from "./definition.ts";

export const roleGrantStatement = (role: string, policy: RolePolicy) =>
  `GRANT ROLE ${quoteIdentifier(policy.role)} TO ROLE ${quoteIdentifier(role)}`;

const grantRole: GrantPolicy<RolePolicy> = async (session, role, policy) => {
  await session.execute(roleGrantStatement(role, policy));
};

/** The role access type: the wrapper role is granted one customer role per
 * policy. */
export const router = (t: AnyConnectorTRPCInstance) =>
  newAgentAccessRouter(t, spec, grantRole);
