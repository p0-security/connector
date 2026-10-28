import { ConnectorError } from "@p0security/connector-core";
import { isEqual } from "lodash-es";

import type { Policy, PolicyRequest, Role } from "./client.ts";

/**
 * The custom roles P0 creates, one per request: what every one of them holds,
 * and how a primitive finds the request's among the organization's roles.
 */

/** The permission behind every database grant: SQL console on the service. */
export const SQL_CONSOLE_ACCESS = "sql-console:database:access";

/** A policy resource for the organization. */
export const organizationResource = (organizationId: string) =>
  `organization/${organizationId}`;

/** A policy resource for one service. */
export const serviceResource = (serviceId: string) => `instance/${serviceId}`;

/** A role's actor for an organization member, by the member's user ID. */
export const userActor = (userId: string) => `user/${userId}`;

/**
 * What every P0 role holds, whatever the access: seeing the organization
 * and the one service. A role is created with these, and a revoke leaves
 * these until the role is deleted.
 */
export const basePolicies = ({
  organizationId,
  serviceId,
}: {
  organizationId: string;
  serviceId: string;
}): PolicyRequest[] => [
  {
    allowDeny: "ALLOW",
    permissions: ["control-plane:organization:view"],
    resources: [organizationResource(organizationId)],
  },
  {
    allowDeny: "ALLOW",
    permissions: ["control-plane:service:view"],
    resources: [serviceResource(serviceId)],
  },
];

/** SQL console on the service, with the policy's tags: the grants, or a console role. */
export const sqlConsolePolicy = (
  serviceId: string,
  tags: NonNullable<PolicyRequest["tags"]>
): PolicyRequest => ({
  allowDeny: "ALLOW",
  permissions: [SQL_CONSOLE_ACCESS],
  resources: [serviceResource(serviceId)],
  tags,
});

/** Every role with exactly the name, in the listing's order. */
export const rolesNamed = (roles: readonly Role[], name: string): Role[] =>
  roles.filter((role) => role.name === name);

/**
 * The role with the name, or `undefined` when there's none. For a grant
 * step: two or more fail as `dependency_violation`, since the connector
 * never picks one to give access through. A revoke step acts on every one
 * instead ({@link rolesNamed}).
 */
export const findRole = (
  roles: readonly Role[],
  { name, organizationId }: { name: string; organizationId: string }
): Role | undefined => {
  const matches = rolesNamed(roles, name);
  const [only, ...others] = matches;
  if (others.length > 0) {
    throw new ConnectorError({
      type: "dependency_violation",
      message: `The ClickHouse Cloud organization ${organizationId} has ${matches.length} roles named ${name}, so P0 can't tell which belongs to the request. Delete all but one of them in the ClickHouse Cloud console, then retry.`,
      payload: { organizationId, role: name, roles: matches.length },
    });
  }
  return only;
};

/**
 * The role with the name, which a grant step needs: the step before it
 * created the role. Missing, it's `object_not_found`. Only a grant calls
 * this: a revoke takes a missing role as gone.
 */
export const requireRole = (
  roles: readonly Role[],
  target: { name: string; organizationId: string }
): Role => {
  const role = findRole(roles, target);
  if (role !== undefined) return role;
  const { name, organizationId } = target;
  throw new ConnectorError({
    type: "object_not_found",
    message: `The ClickHouse Cloud organization ${organizationId} has no role ${name}, which P0 creates as it grants access. Retry the grant.`,
    // `query` is the field P0 reads off an `object_not_found`.
    payload: { organizationId, query: `role ${name}` },
  });
};

/** A policy in the shape a request sends, without empty tags, for comparing. */
const comparable = ({
  allowDeny,
  permissions,
  resources,
  tags,
}: Policy | PolicyRequest): PolicyRequest => {
  const kept = {
    ...(tags?.grants === undefined ? {} : { grants: tags.grants }),
    ...(tags?.roleV2 === undefined ? {} : { roleV2: tags.roleV2 }),
  };
  return {
    allowDeny,
    permissions,
    resources,
    ...(Object.keys(kept).length === 0 ? {} : { tags: kept }),
  };
};

/**
 * Whether the role already holds exactly these policies, in this order, so
 * writing them would change nothing.
 */
export const holdsPolicies = (
  role: Role,
  policies: readonly PolicyRequest[]
): boolean => isEqual(role.policies.map(comparable), policies.map(comparable));
