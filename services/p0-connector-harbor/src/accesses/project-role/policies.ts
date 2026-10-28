import { ConnectorError, type Logger } from "@p0security/connector-core";

import { assertAllowedEmail } from "../../allowlist.ts";
import { HarborError, isStatus } from "../../harbor/api.ts";
import type { ConnectHarbor, HarborClient } from "../../harbor/client.ts";
import { callHarbor } from "../../harbor/errors.ts";
import {
  knownRoleOf,
  ranksBelow,
  roleId,
  roleOf,
  unknownRole,
} from "../../harbor/roles.ts";
import { duplicateEmail, refusal } from "../../refusals.ts";
import { type HarborRole, hostOf } from "./definition.ts";
import type { ResourceSchema } from "./handler.ts";

/** Where a policy acts, for calls, messages and log lines. */
type Target = {
  harbor: HarborClient;
  host: string;
  project: string;
  /** Harbor's user id, read once from the decimal string P0 holds. */
  userId: number;
  /** Bound to the request, the host, the project and the user. No email. */
  log: Logger;
};

const isProjectGone = (error: unknown) =>
  error instanceof HarborError && error.failure.kind === "project_gone";

/** The user's own member row on the project now. Never a group's. */
// TODO(INT-447): the listing is paged by offset, so a row a concurrent delete
// shifts across a page boundary can be missed by this one read.
const findOwnRow = ({ harbor, project, userId }: Target) =>
  harbor.findDirectMember(project, userId);

/**
 * The error for a write Harbor answered with success but the member list
 * doesn't show: Harbor answers 200 to a `PUT` or `DELETE` on a member id
 * that isn't the project's, so reading the row again is the only proof.
 * `found` completes "the project's member list shows ...".
 */
const notApplied = (
  { host, project, userId }: Target,
  { found, retry }: { found: string; retry: "grant" | "revoke" }
) =>
  new ConnectorError({
    type: "dependency_violation",
    message: `Harbor at ${host} accepted the change to Harbor user ${userId} on project ${project}, but the project's member list shows ${found}. Check the project's Members tab, then retry the ${retry}.`,
    payload: { host, project, userId },
  });

/**
 * Confirms that `email` is still the email of the Harbor user the grant is
 * for. P0 resolved the user from the email at request time. Since then the
 * user may have been deleted, or the email moved to another user, and the
 * connector must not grant a role to anyone but the principal: so the lookup
 * must find exactly this user. (The allowlist has already run, before the
 * secret was read.)
 */
const confirmIdentity = async (
  { harbor, host, userId, log }: Target,
  email: string
) => {
  const users = await harbor.findUsersByEmail(email);
  if (users.length > 1) throw duplicateEmail({ host, email, users });
  const [found] = users;
  if (found?.userId !== userId) {
    // The ids say what happened, for whoever reads the log. Never the email.
    log.info(
      { foundUserId: found?.userId ?? null },
      "the email no longer resolves to the user the grant is for; refusing"
    );
    // INT-231's grant-time copy: the user is gone, or the email moved.
    throw refusal({
      reason: "no_user",
      message: `The Harbor user for ${email} on ${host} no longer exists, or its email changed. Request access again.`,
      payload: { host, userId },
    });
  }
};

/**
 * Adds the user to the project with `role`. Answers `"conflict"` for
 * Harbor's 409, which says they have a direct member row already.
 */
const add = async (
  { harbor, project, userId, log }: Target,
  role: HarborRole
): Promise<"added" | "conflict"> => {
  try {
    await harbor.addMember(project, { userId, roleId: roleId(role) });
    log.info("added the user to the project");
    return "added";
  } catch (error) {
    if (!isStatus(error, 409)) throw error;
    log.info("Harbor says the user is a member already; reading again");
    return "conflict";
  }
};

/**
 * Leaves the user with at least `role` on the project: adds them as a direct
 * member, or raises their direct role. Group rows are never touched.
 *
 * It never lowers. A grant that finds an equal or higher direct role
 * succeeds without a write, and the revoke at expiry then removes or lowers
 * a role P0 never gave. P0 refuses such a request before it gets here: at
 * request time (INT-386), and again when it stages the grant (INT-398). A
 * role someone raises outside P0 between the stage and the grant is accepted
 * drift: it is lowered or removed with the request, as databricks does.
 *
 * Read, compare, write isn't atomic: Harbor has no conditional write. What
 * keeps two grants or a grant and a revoke for the same user apart is P0's
 * lock on the user body, not anything here.
 */
const grant = async (target: Target, role: HarborRole) => {
  const { harbor, host, project, userId, log } = target;
  const where = { host, project, userId: String(userId) };
  let row = await findOwnRow(target);
  if (row === undefined) {
    const outcome = await add(target, role);
    row = await findOwnRow(target);
    if (row === undefined && outcome === "conflict") {
      // Harbor's member list is believed to leave out a row whose role id
      // isn't one of its five, which would look like this.
      throw new ConnectorError({
        type: "dependency_violation",
        message: `Harbor at ${host} answered 409 to adding Harbor user ${userId} to project ${project}, but the member list shows no direct role for them. They may hold a role Harbor doesn't list. Ask a Harbor admin to remove them from the project's Members tab, then retry the grant.`,
        payload: { host, project, userId },
      });
    }
    if (row === undefined) {
      throw notApplied(target, {
        found: "no direct role for them",
        retry: "grant",
      });
    }
  }
  const current = knownRoleOf(row, where, "grant");
  if (!ranksBelow(current, role)) return;

  await harbor.updateMember(project, {
    memberId: row.memberId,
    roleId: roleId(role),
  });
  log.info({ from: current }, "raised the user's direct role");
  const after = await findOwnRow(target);
  if (after === undefined) {
    throw notApplied(target, {
      found: "no direct role for them",
      retry: "grant",
    });
  }
  const now = knownRoleOf(after, where, "grant");
  if (ranksBelow(now, role)) {
    throw notApplied(target, {
      found: `the role ${now}, not ${role}`,
      retry: "grant",
    });
  }
};

/**
 * Ends P0's grant: puts `priorRole` back, or removes the user when they had
 * none. Group rows are never touched.
 *
 * It only ever lowers (A1): `priorRole` goes back only when it ranks below
 * the role the user holds now, and an equal or higher role is left as it is.
 * Revoke skips the allowlist and the identity check, so taking access away
 * never depends on either, and an unbounded restore would let a tampered P0
 * raise anyone.
 *
 * It is bound to nothing P0 granted: the connector can't tell whether the
 * role it lowers or removes is one P0 gave, only that P0 says its grant is
 * over. A1 accepts that. As for a grant, read, compare, write isn't atomic,
 * and P0's lock on the user body is what keeps calls for one user apart.
 *
 * Already done: no direct member row (someone removed them during the
 * grant), or a project that no longer exists.
 */
const revoke = async (target: Target, priorRole: HarborRole | null) => {
  const { harbor, host, project, userId, log } = target;
  try {
    const row = await findOwnRow(target);
    if (row === undefined) {
      log.info("the user has no direct role on the project; already revoked");
      return;
    }
    const current = roleOf(row.roleId);
    if (priorRole === null) {
      // A1: with no prior role the member goes, whatever role they hold,
      // one P0 doesn't know included.
      await harbor.removeMember(project, row.memberId);
      log.info({ from: current ?? row.roleId }, "removed the user");
      if ((await findOwnRow(target)) !== undefined) {
        throw notApplied(target, {
          found: "them still a direct member",
          retry: "revoke",
        });
      }
      return;
    }
    // Whether `priorRole` ranks below a role P0 doesn't know can't be told,
    // so nothing changes and the revoke fails, where an admin will see it.
    if (current === undefined) {
      throw unknownRole(
        row,
        { host, project, userId: String(userId) },
        "revoke"
      );
    }
    if (!ranksBelow(priorRole, current)) {
      log.info(
        { current, priorRole },
        "the user's direct role doesn't rank above the prior role; leaving it"
      );
      return;
    }
    await harbor.updateMember(project, {
      memberId: row.memberId,
      roleId: roleId(priorRole),
    });
    log.info(
      { from: current, to: priorRole },
      "restored the user's prior role"
    );
    const after = await findOwnRow(target);
    const now = after === undefined ? undefined : roleOf(after.roleId);
    if (now !== priorRole) {
      throw notApplied(target, {
        found:
          after === undefined
            ? "no direct role for them"
            : `the role ${now ?? `id ${after.roleId}`}, not the prior role ${priorRole}`,
        retry: "revoke",
      });
    }
  } catch (error) {
    if (!isProjectGone(error)) throw error;
    // The client reads a bare 404 on a project's route as `project_gone`,
    // and a proxy or an ingress's default backend answers 404 to everything.
    // "Already revoked" leaves access in place if it is wrong, so before
    // saying it: this is Harbor answering, and Harbor says the project is
    // gone.
    await harbor.systemInfo();
    if (await harbor.projectExists(project)) {
      throw new ConnectorError({
        type: "dependency_violation",
        message: `Harbor at ${host} answered that project ${project} doesn't exist while P0 was taking back Harbor user ${userId}'s role, but the project exists. Check the project's Members tab, then retry the revoke.`,
        payload: { host, project, userId },
      });
    }
    log.info("the project no longer exists; already revoked");
  }
};

/**
 * `setPoliciesForUser`: P0 sends exactly one policy, the role to leave the
 * user with on one project. A role is a grant; `null` is a revoke.
 */
export const setPolicies = async ({
  connect,
  logger,
  context,
  userId,
  policies,
}: {
  connect: ConnectHarbor;
  logger: Logger;
  context: ResourceSchema["RequestContext"];
  userId: ResourceSchema["UserId"];
  policies: ResourceSchema["Policy"][];
}): Promise<void> => {
  const { requestId, email, priorRole } = context;
  const [policy, ...others] = policies;
  if (policy === undefined || others.length > 0) {
    // `unknown`, not `validation_error`: P0 sends exactly one policy, so
    // anything else is a P0 bug the requester can't correct.
    throw new ConnectorError({
      type: "unknown",
      message: `Expected exactly 1 policy for a Harbor project role, got ${policies.length}`,
      payload: { requestId, nPolicies: policies.length },
    });
  }
  const { project, role } = policy;
  const host = hostOf(context);
  // No email in the bindings: it is only checked, never logged.
  const log = logger.child({ requestId, host, project, userId, role });
  // A grant checks the email's domain first, before the secret is read or
  // Harbor is called. A revoke never does.
  if (role !== null) assertAllowedEmail(email, log);
  const target: Target = {
    harbor: await connect(context, log),
    host,
    project,
    // The schema holds `userId` to a canonical decimal, so it reads exactly.
    userId: Number(userId),
    log,
  };
  await callHarbor(async () => {
    if (role === null) return await revoke(target, priorRole);
    await confirmIdentity(target, email);
    await grant(target, role);
  }, host);
};
