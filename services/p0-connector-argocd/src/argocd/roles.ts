import {
  BUILT_IN_ROLES,
  CONNECTOR_ROLE,
  type RbacPolicy,
  isGlobalRole,
  isProjectName,
  isProjectRole,
} from "./policy.ts";

/** The roles P0 can offer on an instance. */
export type ArgoCdRoles = {
  /** Global roles, as `role:<name>`, in order. */
  global: string[];
  /** Each AppProject's roles, by name, both in order. */
  projects: { name: string; roles: string[] }[];
};

/**
 * The roles P0 can grant on the instance whose policy is `policy`.
 *
 * Global roles are Argo CD's built-ins, `role:readonly` and `role:admin`,
 * and every `role:` name a `g` or `p` line names, less the connector's own
 * role and `policy.default`'s, which every user holds already. A name P0
 * wouldn't write, such as one with a `,` or a space in it, is left out, so
 * every role listed is one `buildLine` takes.
 *
 * Project roles are the roles each AppProject defines, of the projects and
 * roles whose names P0 writes.
 */
export const listRoles = (policy: RbacPolicy): ArgoCdRoles => {
  const named = new Set<string>([...BUILT_IN_ROLES, ...policy.permitted]);
  for (const [subject, roles] of policy.inherits) {
    named.add(subject);
    for (const role of roles) named.add(role);
  }
  const global = [...named]
    .filter(
      (role) =>
        isGlobalRole(role) &&
        role !== CONNECTOR_ROLE &&
        role !== policy.defaultRole
    )
    .sort();
  const projects = policy.projects
    .filter(({ name }) => isProjectName(name))
    .map(({ name, roles }) => ({
      name,
      roles: roles
        .map((role) => role.name)
        .filter(isProjectRole)
        .sort(),
    }))
    // AppProject names are unique, so no two compare equal.
    .sort((a, b) => (a.name < b.name ? -1 : 1));
  return { global, projects };
};
