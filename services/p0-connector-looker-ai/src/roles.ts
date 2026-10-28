import { ConnectorError } from "@p0security/connector";

import type { Level } from "./accesses/model/definition.ts";
import {
  type LookerModelSet,
  type LookerPermissionSet,
  type LookerRole,
  type LookerSession,
  createModelSet,
  createPermissionSet,
  createRole,
  findModelSet,
  findPermissionSet,
  findRole,
  listPermissionParents,
} from "./looker/looker-api.ts";

const READ_PERMISSIONS = [
  "access_data",
  "see_looks",
  "see_user_dashboards",
  "see_lookml_dashboards",
  "see_sql",
  "explore",
];

/** The permissions each level asks for, before their parents are added. */
export const LEVEL_PERMISSIONS: Record<Level, readonly string[]> = {
  read: READ_PERMISSIONS,
  edit: [...READ_PERMISSIONS, "save_content", "save_looks", "save_dashboards"],
};

/**
 * Permissions that no role P0 generates may hold, even as a parent of one it
 * asks for: they reach LookML or the whole instance. Looker's API may not
 * enforce the role editor's rules for them (W16), so the connector does.
 */
export const REFUSED_PERMISSIONS: ReadonlySet<string> = new Set([
  "administer",
  "deploy",
  "develop",
  "manage_models",
  "sudo",
]);

type Closure = {
  permissions: ReadonlySet<string>;
  missing: ReadonlySet<string>;
};

/** Adds a permission and its parents to the closure, up to the first one it
 * already has, or the first one the instance doesn't list. */
const followParents = (
  closure: Closure,
  permission: string | null | undefined,
  parents: ReadonlyMap<string, string | null>
): Closure => {
  // The closure stops a parent chain that loops.
  if (!permission || closure.permissions.has(permission)) return closure;
  if (!parents.has(permission)) {
    return { ...closure, missing: new Set([...closure.missing, permission]) };
  }
  const permissions = new Set([...closure.permissions, permission]);
  return followParents(
    { ...closure, permissions },
    parents.get(permission),
    parents
  );
};

/**
 * Adds every permission that a wanted one depends on, following `parent`
 * until it reaches one already in the set.
 *
 * @param parents Each permission the instance knows, with its parent, from
 *   {@link listPermissionParents}
 * @returns `permissions`: the wanted ones and their parents, sorted.
 *   `missing`: the ones the instance doesn't list, sorted.
 */
export const closeOverParents = (
  wanted: readonly string[],
  parents: ReadonlyMap<string, string | null>
): { permissions: string[]; missing: string[] } => {
  const { permissions, missing } = wanted.reduce<Closure>(
    (closure, permission) => followParents(closure, permission, parents),
    { permissions: new Set<string>(), missing: new Set<string>() }
  );
  return { permissions: [...permissions].sort(), missing: [...missing].sort() };
};

/**
 * The permissions of a level, with their parents, on this instance.
 *
 * @throws {ConnectorError} when the instance doesn't list one of them, or
 *   when one of them is refused
 */
export const toLevelPermissions = (
  level: Level,
  parents: ReadonlyMap<string, string | null>
): string[] => {
  const { permissions, missing } = closeOverParents(
    LEVEL_PERMISSIONS[level],
    parents
  );
  if (missing.length > 0) {
    throw new ConnectorError({
      type: "unknown",
      message: `The Looker instance doesn't have the permissions that P0's ${level} level needs: ${missing.join(", ")}`,
      payload: { level, missing: missing.join(",") },
    });
  }
  const refused = permissions.filter((permission) =>
    REFUSED_PERMISSIONS.has(permission)
  );
  if (refused.length > 0) {
    throw new ConnectorError({
      type: "unknown",
      message: `On this Looker instance, P0's ${level} level would include ${refused.join(", ")}, which P0 never grants`,
      payload: { level, refused: refused.join(",") },
    });
  }
  return permissions;
};

export const toPermissionSetName = (level: Level) => `p0-looker-ai-${level}`;

export const toModelSetName = (model: string) => `p0-looker-ai-model-${model}`;

// The level is always the last part, so no two models and levels give one
// name.
export const toRoleName = (model: string, level: Level) =>
  `p0-looker-ai-${model}-${level}`;

const toDifferences = (found: readonly string[], wanted: readonly string[]) => {
  const extra = found.filter((item) => !wanted.includes(item)).sort();
  const lacking = wanted.filter((item) => !found.includes(item)).sort();
  return [
    ...(extra.length > 0 ? [`it also has ${extra.join(", ")}`] : []),
    ...(lacking.length > 0 ? [`it lacks ${lacking.join(", ")}`] : []),
  ];
};

/**
 * Finds the object with P0's name, or creates it, and checks that it is what
 * P0 wants.
 *
 * Grants reuse these objects, and a Looker admin can edit them, so an object
 * that differs fails the grant: a grant that reused it would give more, or
 * less, than the level P0 shows. Nothing here changes an object it finds.
 *
 * Two grants can race to create an object. When Looker refuses a create
 * because the name is taken, this searches again and uses what it finds.
 */
const setLookerObject = async <T>(object: {
  kind: string;
  name: string;
  find: () => Promise<T | undefined>;
  create: () => Promise<T>;
  /** How the object differs from P0's, or nothing when it doesn't */
  differences: (found: T) => string[];
}): Promise<T> => {
  const { kind, name, find, create } = object;
  const found =
    (await find()) ??
    (await create().catch(async (error: unknown) => {
      if (
        !(error instanceof ConnectorError) ||
        error.data.type !== "already_exists"
      ) {
        throw error;
      }
      const raced = await find();
      if (raced === undefined) throw error;
      return raced;
    }));
  const problems = object.differences(found);
  if (problems.length > 0) {
    throw new ConnectorError({
      type: "unknown",
      message: `The Looker ${kind} ${name} isn't the one P0 made: ${problems.join("; ")}. P0 won't grant access with it. Change it back, or delete it so that P0 makes it again.`,
      payload: { kind, name },
    });
  }
  return found;
};

const setPermissionSet = (
  session: LookerSession,
  level: Level,
  permissions: string[]
) => {
  const name = toPermissionSetName(level);
  return setLookerObject<LookerPermissionSet>({
    kind: "permission set",
    name,
    find: () => findPermissionSet(session, name),
    create: () => createPermissionSet(session, { name, permissions }),
    differences: (found) => toDifferences(found.permissions, permissions),
  });
};

const setModelSet = (session: LookerSession, model: string) => {
  const name = toModelSetName(model);
  return setLookerObject<LookerModelSet>({
    kind: "model set",
    name,
    find: () => findModelSet(session, name),
    create: () => createModelSet(session, { name, models: [model] }),
    differences: (found) => toDifferences(found.models, [model]),
  });
};

const setRole = (
  session: LookerSession,
  role: {
    model: string;
    level: Level;
    permissionSetId: string;
    modelSetId: string;
  }
) => {
  const { model, level, permissionSetId, modelSetId } = role;
  const name = toRoleName(model, level);
  return setLookerObject<LookerRole>({
    kind: "role",
    name,
    find: () => findRole(session, name),
    create: () => createRole(session, { name, permissionSetId, modelSetId }),
    differences: (found) => [
      ...(found.permissionSetId !== permissionSetId
        ? [`its permission set isn't ${toPermissionSetName(level)}`]
        : []),
      ...(found.modelSetId !== modelSetId
        ? [`its model set isn't ${toModelSetName(model)}`]
        : []),
    ],
  });
};

/**
 * Finds or creates P0's role for a model and a level, with its permission set
 * and its model set. Nothing is ever deleted: other grants may use them.
 *
 * @returns The role's id
 */
export const setModelRole = async (
  session: LookerSession,
  grant: { model: string; level: Level }
): Promise<string> => {
  const { model, level } = grant;
  const permissions = toLevelPermissions(
    level,
    await listPermissionParents(session)
  );
  const permissionSet = await setPermissionSet(session, level, permissions);
  const modelSet = await setModelSet(session, model);
  const role = await setRole(session, {
    model,
    level,
    permissionSetId: permissionSet.id,
    modelSetId: modelSet.id,
  });
  return role.id;
};
