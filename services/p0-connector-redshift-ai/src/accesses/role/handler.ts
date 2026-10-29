import type { AnyConnectorTRPCInstance } from "@p0security/connector";

import type { RequestContext } from "../../context.ts";
import { quoteIdentifier, quoteUserName } from "../../sql.ts";
import { type AgentAccess, newAgentAccessRouter } from "../router.ts";
import { type RolePolicy, spec } from "./definition.ts";

export const roleGrantStatement = (user: string, { role }: RolePolicy) =>
  `GRANT ROLE ${quoteIdentifier(role)} TO ${quoteUserName(user)}`;

const roleAccess: AgentAccess<RolePolicy, RequestContext> = {
  grant: async (session, _context, user, policies) => {
    await session.batch(
      policies.map((policy) => roleGrantStatement(user, policy))
    );
  },
  privilegeRoles: () => [],
};

/** The role access type: the agent's user is granted one customer role per
 * policy. */
export const router = (t: AnyConnectorTRPCInstance) =>
  newAgentAccessRouter(t, spec, roleAccess);
