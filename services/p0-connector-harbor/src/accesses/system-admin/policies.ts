import { ConnectorError, type Logger } from "@p0security/connector-core";

import { assertAllowedEmail } from "../../allowlist.ts";
import { isStatus } from "../../harbor/api.ts";
import type { ConnectHarbor, HarborClient } from "../../harbor/client.ts";
import { callHarbor, toConnectorError } from "../../harbor/errors.ts";
import { duplicateEmail, refusal } from "../../refusals.ts";
import { hostOf } from "../project-role/definition.ts";
import type { ResourceSchema } from "./handler.ts";

type RequestContext = ResourceSchema["RequestContext"];

/** Where a policy acts, for calls, messages and log lines. */
type Target = {
  /** The admin user's client, for every call. */
  harbor: HarborClient;
  host: string;
  /** Harbor's user id, read once from the decimal string P0 holds. */
  userId: number;
  /** Bound to the request, the host and the user. No email. */
  log: Logger;
};

/**
 * The error for a write Harbor answered with success but the user list
 * doesn't show. `found` completes "the user list shows ...".
 */
const notApplied = (
  { host, userId }: Target,
  { found, retry }: { found: string; retry: "grant" | "revoke" }
) =>
  new ConnectorError({
    type: "dependency_violation",
    message: `Harbor at ${host} accepted the change to Harbor user ${userId}'s system administrator flag, but the user list shows ${found}. Check the user on Harbor's Users page, then retry the ${retry}.`,
    payload: { host, userId },
  });

/** The `no_user` refusal, in the project role's words (INT-231). */
const noUser = (host: string, userId: number, email: string) =>
  refusal({
    reason: "no_user",
    message: `The Harbor user for ${email} on ${host} no longer exists, or its email changed. Request access again.`,
    payload: { host, userId },
  });

/**
 * Sets or clears the user's flag. Harbor answers 404 for a user that doesn't
 * exist: `"gone"`.
 */
const write = async (
  { harbor, host, userId }: Target,
  sysadmin: boolean
): Promise<"gone" | "written"> => {
  try {
    await harbor.setSysadmin(userId, sysadmin);
    return "written";
  } catch (error) {
    if (isStatus(error, 404)) return "gone";
    throw toConnectorError(error, host);
  }
};

/**
 * Makes the user a Harbor system administrator, by its `sysadmin_flag`.
 *
 * First, as for a project role, the email must still belong to exactly this
 * user: P0 resolved the user from the email at request time, and the
 * connector must not make anyone but the principal an administrator. That
 * read is the user list's, and it gives the user's flag too. A user who has it already is left as they are: P0 refuses such
 * a request before it gets here, and a flag set between the stage and the
 * grant is accepted drift, cleared with the request, as for a project role.
 *
 * Then the flag is set, and read again through the user list. Read, compare, write isn't atomic: P0's lock on the user body is
 * what keeps calls for one user apart.
 */
const grant = async (target: Target, email: string) => {
  const { harbor, host, userId, log } = target;
  const users = await callHarbor(
    () => harbor.findUserAdminsByEmail(email),
    host
  );
  if (users.length > 1) throw duplicateEmail({ host, email, users });
  const [found] = users;
  if (found?.userId !== userId) {
    log.info(
      { foundUserId: found?.userId ?? null },
      "the email no longer resolves to the user the grant is for; refusing"
    );
    throw noUser(host, userId, email);
  }
  if (found.sysadminFlag) {
    log.info("the user is a system administrator already; leaving them");
    return;
  }
  if ((await write(target, true)) === "gone") throw noUser(host, userId, email);
  log.info("made the user a system administrator");
  const after = await callHarbor(() => harbor.findUserAdminById(userId), host);
  if (!after?.sysadminFlag) {
    throw notApplied(target, {
      found: after === undefined ? "no such user" : "the flag not set",
      retry: "grant",
    });
  }
};

/**
 * Ends P0's grant: clears the user's `sysadmin_flag`, unless they had it
 * before P0 granted. It never sets the flag, so a tampered P0 can't use a
 * revoke to make anyone an administrator. It skips the allowlist and the
 * identity check, so taking access away never depends on either.
 *
 * It is bound to nothing P0 granted: the connector can't tell whether the
 * flag it clears is one P0 set, only that P0 says its grant is over and the
 * user didn't have it before.
 *
 * Already done: the user doesn't have the flag now, or no such user
 * exists. (A user who had it before P0 granted never gets here.)
 */
const revoke = async (target: Target) => {
  const { harbor, host, userId, log } = target;
  const current = await callHarbor(
    () => harbor.findUserAdminById(userId),
    host
  );
  if (!current?.sysadminFlag) {
    log.info(
      { exists: current !== undefined },
      "the user isn't a system administrator; already revoked"
    );
    return;
  }
  const outcome = await write(target, false);
  const after = await callHarbor(() => harbor.findUserAdminById(userId), host);
  if (outcome === "gone" && after === undefined) {
    log.info("the user no longer exists; already revoked");
    return;
  }
  if (after?.sysadminFlag) {
    throw notApplied(target, { found: "the flag still set", retry: "revoke" });
  }
  log.info("cleared the user's system administrator flag");
};

/**
 * `setPoliciesForUser`: P0 sends exactly one policy. `systemAdmin: true` is
 * a grant, and `false` a revoke.
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
  context: RequestContext;
  userId: ResourceSchema["UserId"];
  policies: ResourceSchema["Policy"][];
}): Promise<void> => {
  const { requestId, email, wasSystemAdmin } = context;
  const [policy, ...others] = policies;
  if (policy === undefined || others.length > 0) {
    // `unknown`, not `validation_error`: P0 sends exactly one policy, so
    // anything else is a P0 bug the requester can't correct.
    throw new ConnectorError({
      type: "unknown",
      message: `Expected exactly 1 policy for Harbor system administrator, got ${policies.length}`,
      payload: { requestId, nPolicies: policies.length },
    });
  }
  const { systemAdmin } = policy;
  const host = hostOf(context);
  // No email in the bindings: it is only checked, never logged.
  const log = logger.child({ requestId, host, userId, systemAdmin });
  if (systemAdmin && wasSystemAdmin) {
    // A revoke leaves the flag of a user who had it before P0 granted. So if
    // the flag was cleared after the stage, a grant here would make them an
    // administrator for good. P0 refuses a request from an administrator, so
    // this is P0's record and the user disagreeing: refuse, before any
    // secret is read or Harbor is called.
    throw new ConnectorError({
      type: "validation_error",
      message:
        "P0 recorded that this user was already a Harbor system administrator when it staged the request, and the revoke would leave the flag in place, so the connector won't grant it. Request access again.",
      payload: { requestId },
    });
  }
  if (!systemAdmin && wasSystemAdmin) {
    // The flag was the user's before P0 granted, so it stays: no secret is
    // read and Harbor isn't called.
    log.info(
      "the user was a system administrator before P0 granted; leaving them"
    );
    return;
  }
  // A grant checks the email's domain first, before a secret is read or
  // Harbor is called. A revoke never does.
  if (systemAdmin) assertAllowedEmail(email, log);
  const target: Target = {
    harbor: await connect(context, log),
    host,
    // The schema holds `userId` to a canonical decimal, so it reads exactly.
    userId: Number(userId),
    log,
  };
  if (systemAdmin) await grant(target, email);
  else await revoke(target);
};
