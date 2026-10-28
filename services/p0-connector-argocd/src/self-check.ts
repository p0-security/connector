import type { ArgoCdClient } from "./argocd/client.ts";
import { refusal } from "./refusals.ts";

/** A permission, as an `argocd-rbac-cm` `p` line names it. */
export type Permission = { resource: string; action: string; object: string };

/**
 * What the `p0-connector` account must never be allowed: each would let
 * whoever holds its token do far more than write its own policy key. It
 * needs `applications, get` and a fine-grained `update` on the managing
 * Application, and `projects, get`, and nothing on this list.
 */
export const FORBIDDEN_PERMISSIONS: readonly Permission[] = [
  { resource: "applications", action: "sync", object: "*/*" },
  { resource: "applications", action: "delete", object: "*/*" },
  { resource: "projects", action: "update", object: "*" },
  { resource: "accounts", action: "update", object: "*" },
  { resource: "clusters", action: "update", object: "*" },
];

/** `applications, sync, *\/*`, as a policy line and a message write it. */
export const formatPermission = ({ resource, action, object }: Permission) =>
  `${resource}, ${action}, ${object}`;

/**
 * Which of {@link FORBIDDEN_PERMISSIONS} the account holds, in that order,
 * as Argo CD's `can-i` answers for the account itself.
 *
 * Call `userInfo` first: with anonymous access on, Argo CD answers a token
 * it doesn't accept as an anonymous caller, and `can-i` would then answer
 * for the anonymous user.
 */
export const heldForbiddenPermissions = async (
  argocd: ArgoCdClient
): Promise<Permission[]> => {
  const answers = await Promise.all(
    FORBIDDEN_PERMISSIONS.map(({ resource, action, object }) =>
      argocd.canI(resource, action, object)
    )
  );
  return FORBIDDEN_PERMISSIONS.filter((_, index) => answers[index] === true);
};

/**
 * The privilege self-check: refuses with `self_check_failed` when the
 * account holds any of {@link FORBIDDEN_PERMISSIONS}. Runs before every
 * grant, so a connector whose account was given too much grants nothing
 * until it is cut back.
 */
export const assertLeastPrivilege = async (
  argocd: ArgoCdClient,
  host: string
): Promise<void> => {
  const held = await heldForbiddenPermissions(argocd);
  if (held.length === 0) return;
  const named = held.map(formatPermission);
  throw refusal({
    reason: "self_check_failed",
    message: `The p0-connector account on Argo CD at ${host} may do more than the connector needs (${named.map((p) => `"${p}"`).join(", ")}), so the connector grants nothing. Remove those permissions from the account's role in argocd-rbac-cm.`,
    payload: { host, held: named.join("; ") },
  });
};
