import { ConnectorError, type Logger } from "@p0security/connector";
import { range } from "lodash-es";
import { setTimeout as sleep } from "node:timers/promises";

import { hostOf } from "../../account.ts";
import { validateAllowedEmail } from "../../allowlist.ts";
import {
  LaunchDarklyError,
  isStatus,
  statusOf,
} from "../../launchdarkly/api.ts";
import {
  type LaunchDarklyClient,
  type MemberState,
  connectLaunchDarkly,
  foldAsciiCase,
  unlessNotFound,
} from "../../launchdarkly/client.ts";
import { callLaunchDarkly } from "../../launchdarkly/errors.ts";
import { refusal } from "../../refusals.ts";
import type { BaseRequestContext } from "./definition.ts";

/** The accesses, for log lines. */
export const ACCESSES = ["base-role"] as const;

export type Access = (typeof ACCESSES)[number];

/** Waits `ms` milliseconds. Tests pass one that doesn't wait. */
export type Pause = (ms: number) => Promise<void>;

export const pauseFor: Pause = async (ms) => {
  await sleep(ms);
};

/** How many times a grant reads the member back to see its change. */
export const READ_BACK_READS = 3;

/** How long a grant waits between reading the member back. */
export const READ_BACK_PAUSE_MS = 1000;

/** The member a call acts on, and what it acts with. */
export type Target = {
  launchDarkly: LaunchDarklyClient;
  /** The instance's host, which stands for the account in messages. */
  host: string;
  memberId: string;
  requestId: string;
  /** Bound to the request, the host, the member and the access. No email. */
  log: Logger;
  pause: Pause;
};

/**
 * The member, or `undefined` when LaunchDarkly has none with the id: a
 * revoke has nothing left to take back from a member who is gone.
 */
export const memberForRevoke = async ({
  launchDarkly,
  memberId,
  log,
}: Target): Promise<MemberState | undefined> => {
  const member = await unlessNotFound(() => launchDarkly.fetchMember(memberId));
  if (member === undefined) {
    log.info(
      "LaunchDarkly has no such member, so there is nothing to take back"
    );
  }
  return member;
};

/** The longest a read back waits after LaunchDarkly limits it. */
export const READ_BACK_MAX_PAUSE_MS = 2000;

/**
 * How long to wait before reading the member back again after `error`, or
 * `undefined` when the error isn't one a later read can get past: a 429
 * waits its `Retry-After`, up to {@link READ_BACK_MAX_PAUSE_MS}, and a 5xx
 * or no answer waits {@link READ_BACK_PAUSE_MS}.
 */
const pauseAfter = (error: unknown): number | undefined => {
  if (!(error instanceof LaunchDarklyError)) return undefined;
  const { failure } = error;
  if (failure.kind === "unreachable") return READ_BACK_PAUSE_MS;
  if (failure.kind !== "status") return undefined;
  if (failure.status === 429) {
    return failure.retryAfter === undefined
      ? READ_BACK_PAUSE_MS
      : Math.min(failure.retryAfter * 1000, READ_BACK_MAX_PAUSE_MS);
  }
  return failure.status >= 500 ? READ_BACK_PAUSE_MS : undefined;
};

/**
 * Reads the member back after a grant's write, up to
 * {@link READ_BACK_READS} times, {@link READ_BACK_PAUSE_MS} apart, until
 * `visible` says the change is there. A read that LaunchDarkly limits
 * (429), fails (5xx) or doesn't answer counts as not showing the change
 * yet, except the last, whose failure stands. A change LaunchDarkly
 * accepted but doesn't show fails the grant, and P0 then takes back
 * whatever it did apply.
 */
export const confirmGrant = async (
  target: Target,
  { what, visible }: { what: string; visible: (member: MemberState) => boolean }
): Promise<void> => {
  const { launchDarkly, host, memberId, log } = target;
  // How long to wait before the next read, or `undefined` once it shows.
  const readBack = async (read: number): Promise<number | undefined> => {
    try {
      const member = await launchDarkly.fetchMember(memberId);
      return visible(member) ? undefined : READ_BACK_PAUSE_MS;
    } catch (error) {
      const after = pauseAfter(error);
      if (after === undefined || read >= READ_BACK_READS) throw error;
      log.info(
        { read, status: statusOf(error) },
        "reading the member back failed, so it is read again"
      );
      return after;
    }
  };
  for (const read of range(1, READ_BACK_READS + 1)) {
    const wait = await readBack(read);
    if (wait === undefined) return;
    if (read < READ_BACK_READS) await target.pause(wait);
  }
  log.warn({ reads: READ_BACK_READS }, "the member doesn't show the grant");
  throw new ConnectorError({
    message: `LaunchDarkly at ${host} accepted ${what} for member ${memberId}, but reading the member back ${READ_BACK_READS} times didn't show it, so P0 takes the change back. An identity provider using SSO or SCIM may have undone it. Request access again once the member keeps changes.`,
    payload: { host, memberId },
    type: "dependency_violation",
  });
};

/** What about the member changed since P0 resolved them. */
type Changed =
  | "account"
  | "deleted"
  | "email"
  | "pending_invite"
  | "unverified";

/** The refusal for a member that isn't the one P0 resolved at request time. */
const memberChanged = ({ host, memberId, log }: Target, changed: Changed) => {
  // What changed, for whoever reads the log. Never the email.
  if (changed === "account") {
    log.warn(
      { changed },
      "refused the grant: the access token belongs to another account"
    );
  } else {
    log.info(
      { changed },
      "refused the grant: the member isn't the one P0 resolved"
    );
  }
  const gone = `LaunchDarkly member ${memberId} on ${host} is no longer the member P0 found for the requester: they were deleted, their email changed, or they haven't verified it or joined. Request access again.`;
  const messages: Record<Changed, string> = {
    account: `The LaunchDarkly connector's access token on ${host} belongs to another account than the one P0 found member ${memberId} on. Check the token in the account's secret, then request access again.`,
    deleted: gone,
    email: gone,
    pending_invite: gone,
    unverified: gone,
  };
  return refusal({
    message: messages[changed],
    payload: { changed, host, memberId },
    reason: "member_changed",
  });
};

/**
 * Checks, before a grant writes anything, that the member is still the one
 * P0 resolved from the principal's email at request time, and returns
 * them. The domain allowlist has already run, before the secret was read.
 *
 * - The access token must still belong to the account P0 resolved the
 *   member on, and must not be the member's own (`own_member`).
 * - The member must still exist, have the principal's email (ignoring ASCII
 *   case), have verified it, and have joined (`member_changed`).
 *   LaunchDarkly lets members change their own email, so an unverified one
 *   could be a colleague's.
 */
const validateGrantee = async (
  target: Target,
  { accountId, email }: BaseRequestContext
): Promise<MemberState> => {
  const { launchDarkly, host, memberId, log } = target;
  const caller = await launchDarkly.fetchCallerIdentity();
  if (caller.accountId !== accountId) throw memberChanged(target, "account");
  // Only a personal token acts as a member, which it never changes.
  if (caller.tokenOwnerMemberId === memberId) {
    log.info("refused the grant: the member is the access token's own");
    throw refusal({
      message: `LaunchDarkly member ${memberId} on ${host} is the one the connector's access token acts as, and the connector never changes its own member. Ask your P0 admin to give the account another admin's token.`,
      payload: { host, memberId },
      reason: "own_member",
    });
  }
  const member = await unlessNotFound(() => launchDarkly.fetchMember(memberId));
  if (member === undefined) throw memberChanged(target, "deleted");
  if (foldAsciiCase(member.email) !== foldAsciiCase(email)) {
    throw memberChanged(target, "email");
  }
  if (member.pendingInvite) throw memberChanged(target, "pending_invite");
  if (!member.verified) throw memberChanged(target, "unverified");
  return member;
};

/**
 * Checks, before a revoke writes anything, that the access token still
 * belongs to the account P0 granted on. A revoke acts on the recorded
 * member id, so with another account's token it would find no such member
 * and be done, leaving the access in place.
 *
 * Fails with `insufficient_privileges`, not a refusal: P0 treats a refusal
 * as done, and the access is still there to take back once the secret
 * holds the right token.
 */
const validateRevokeAccount = async (
  { launchDarkly, host, memberId, log }: Target,
  { accountId }: BaseRequestContext
): Promise<void> => {
  const caller = await launchDarkly.fetchCallerIdentity();
  if (caller.accountId === accountId) return;
  log.warn(
    "took nothing back: the access token belongs to another account than the request's"
  );
  throw new ConnectorError({
    message: `The LaunchDarkly connector's access token on ${host} belongs to another account than the one P0 granted access on for member ${memberId}, so P0 took nothing back. Put the account's own token in its secret, then retry the revoke.`,
    payload: { host, memberId },
    type: "insufficient_privileges",
  });
};

/**
 * A 404 during a grant, as P0 shows it: a `validation_error` that says
 * what to do, since `object_not_found` reaches the requester as a bare
 * "Not found". Anything else passes as it is.
 */
const notFoundAtGrant = (error: unknown, host: string): unknown => {
  if (!isStatus(error, 404)) return error;
  const { method, route } = error.call;
  return new ConnectorError({
    message: `LaunchDarkly at ${host} found nothing for ${method} ${route} (404) while P0 was granting access: the member may have been deleted since the request. Request access again.`,
    payload: { host, status: 404 },
    type: "validation_error",
  });
};

/**
 * `setPoliciesForUser`, for the access: works out whether the call
 * grants or revokes, runs a grant's checks, and maps LaunchDarkly's
 * failures onto the errors P0 shows.
 *
 * A call is a revoke when `operation` says so, or when `held` is false:
 * the request's own target isn't in `policies`. P0 sets `operation` from
 * the request's status, so the call that rolls back a failed grant still
 * says `grant`, and only its policies show it is a revoke. Every other
 * target in `policies` is a sibling request's, on the same member and
 * account, which a revoke leaves in place. The two disagreeing is logged as
 * a warning, since only a rollback should.
 *
 * A grant checks the email's domain first, before the secret is read, then
 * the member (`validateGrantee`), then hands over to `grant`, which makes
 * every refusal of its own before it writes. A revoke checks neither the
 * domain nor the member: taking access away mustn't depend on them. It
 * checks only that the token still belongs to the request's account
 * (`validateRevokeAccount`).
 */
export const setMemberPolicies = async ({
  access,
  logger,
  pause,
  context,
  memberId,
  held,
  grant,
  revoke,
}: {
  access: Access;
  logger: Logger;
  pause: Pause;
  context: BaseRequestContext;
  memberId: string;
  /** Whether `policies` hold the request's own target. */
  held: boolean;
  grant: (target: Target, member: MemberState) => Promise<void>;
  revoke: (target: Target) => Promise<void>;
}): Promise<void> => {
  const { requestId, email, operation } = context;
  const effectiveOperation =
    operation === "revoke" || !held ? "revoke" : "grant";
  const host = hostOf(context);
  // No email in the bindings: it is only checked, never logged.
  const log = logger.child({
    access,
    effectiveOperation,
    host,
    memberId,
    operation,
    requestId,
  });
  if (operation === "grant" && !held) {
    // A P0 bug that sent a grant without its target would look just like
    // this, so it is never silent.
    log.warn(
      "the call says grant, but the request's own target isn't in its policies, so it is treated as the rollback of a failed grant"
    );
  }
  if (operation === "revoke" && held) {
    log.warn(
      "the call says revoke, but a sibling request still holds the request's own target, which the revoke leaves in place"
    );
  }

  if (effectiveOperation === "grant") validateAllowedEmail(email, log);
  const target: Target = {
    host,
    launchDarkly: await connectLaunchDarkly(context, log),
    log,
    memberId,
    pause,
    requestId,
  };
  if (effectiveOperation === "revoke") {
    await callLaunchDarkly(async () => {
      await validateRevokeAccount(target, context);
      await revoke(target);
    }, host);
    return;
  }
  await callLaunchDarkly(async () => {
    try {
      await grant(target, await validateGrantee(target, context));
    } catch (error) {
      throw notFoundAtGrant(error, host);
    }
  }, host);
};
