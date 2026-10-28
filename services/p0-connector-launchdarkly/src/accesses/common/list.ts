import {
  ConnectorError,
  type Logger,
  throwAssertNever,
} from "@p0security/connector";

import { type Account, hostOf } from "../../account.ts";
import { validateAllowedEmail } from "../../allowlist.ts";
import {
  type LaunchDarklyClient,
  connectLaunchDarkly,
} from "../../launchdarkly/client.ts";
import { callLaunchDarkly } from "../../launchdarkly/errors.ts";
import { refusal } from "../../refusals.ts";
import {
  type ListerQuery,
  type ListerResponse,
  listerQuery,
} from "./definition.ts";

type Query<Type extends ListerQuery["type"]> = Extract<
  ListerQuery,
  { type: Type }
>;

/**
 * Whether the domain allowlist admits `email`. A pattern that is unset or
 * doesn't compile still throws `domain_pattern_unusable`: that is the
 * connector's setup, not the requester's email.
 */
const isEmailAllowed = (email: string, logger: Logger): boolean => {
  try {
    validateAllowedEmail(email, logger);
    return true;
  } catch (error) {
    if (
      error instanceof ConnectorError &&
      error.data.payload.reason === "domain_not_allowed"
    ) {
      return false;
    }
    throw error;
  }
};

/**
 * Checks that the access token belongs to the account P0 has installed,
 * and returns the token's own member id, if it acts as one. With another
 * account's token, a member id or an email would find a member on that
 * account, so the lookup refuses with `member_changed` (`changed:
 * "account"`), as a grant does.
 */
const validateTokenAccount = async (
  launchDarkly: LaunchDarklyClient,
  account: Account,
  logger: Logger
): Promise<string | null> => {
  const caller = await launchDarkly.fetchCallerIdentity();
  if (caller.accountId === account.accountId) return caller.tokenOwnerMemberId;
  const host = hostOf(account);
  logger.warn(
    { changed: "account" },
    "refused the lookup: the access token belongs to another account"
  );
  throw refusal({
    message: `The LaunchDarkly connector's access token on ${host} belongs to another account than the one P0 installed. Check the token in the account's secret, then request access again.`,
    payload: { changed: "account", host },
    reason: "member_changed",
  });
};

/**
 * Runs `read` with a client for the account, and maps LaunchDarkly's
 * failures onto the errors P0 shows.
 */
const queryLaunchDarkly = async (
  account: Account,
  logger: Logger,
  read: (launchDarkly: LaunchDarklyClient) => Promise<ListerResponse>
): Promise<ListerResponse> => {
  const launchDarkly = await connectLaunchDarkly(account, logger);
  return callLaunchDarkly(() => read(launchDarkly), hostOf(account));
};

/**
 * The one member whose email is the principal's, as
 * `[{ key: <member id>, value: <email> }]`, or `[]`.
 *
 * The domain allowlist runs first, before the secret is read or LaunchDarkly
 * is called: an email outside it is `[]`. Then the access token must belong
 * to the account ({@link validateTokenAccount}). Then `[]` unless exactly one
 * member has the email, ignoring ASCII case, and that member has verified
 * it, has joined, and isn't the access token's own member. LaunchDarkly lets
 * members change their own email, so an unverified one could be a
 * colleague's.
 */
const listMember = async (
  { context, email }: Query<"member">,
  logger: Logger
): Promise<ListerResponse> => {
  const none = (reason: string) => {
    logger.info({ reason }, "no LaunchDarkly member for the email");
    return [];
  };
  if (!isEmailAllowed(email, logger)) return none("domain_not_allowed");
  return queryLaunchDarkly(context, logger, async (launchDarkly) => {
    const tokenOwnerMemberId = await validateTokenAccount(
      launchDarkly,
      context,
      logger
    );
    const matches = await launchDarkly.listMembersByEmail(email);
    const [member, ...others] = matches;
    if (member === undefined) return none("no_match");
    if (others.length > 0) return none("several_matches");
    if (member.pendingInvite) return none("pending_invite");
    if (!member.verified) return none("unverified");
    // Only a personal token acts as a member, which it never changes.
    if (member.memberId === tokenOwnerMemberId) return none("own_member");
    return [{ key: member.memberId, value: member.email }];
  });
};

/**
 * What the member holds now: the base role, then each custom role assigned
 * directly, by its id, from the member's own `customRoles`. No custom role
 * is looked up. The access token must belong to the account first
 * ({@link validateTokenAccount}).
 */
const fetchMemberState = async (
  { context, memberId }: Query<"member-state">,
  logger: Logger
): Promise<ListerResponse> =>
  queryLaunchDarkly(context, logger, async (launchDarkly) => {
    await validateTokenAccount(launchDarkly, context, logger);
    const { role, customRoleIds } = await launchDarkly.fetchMember(memberId);
    return [
      { key: "role", value: role },
      ...customRoleIds.map((id) => ({ group: "role", key: id, value: id })),
    ];
  });

/**
 * Answers a {@link ListerQuery}. Each answer is described on
 * {@link listerQuery}.
 *
 * Only `member` is about a person's email, so only it is gated by the
 * domain allowlist.
 */
export const list = async (
  logger: Logger,
  input: ListerQuery
): Promise<ListerResponse> => {
  // The framework runs no `validation` before `list`, so the query is
  // checked again here: each id in it becomes a path segment.
  const query = listerQuery.parse(input);
  switch (query.type) {
    case "member":
      return await listMember(query, logger);
    case "member-state":
      return await fetchMemberState(query, logger);
    default:
      throw throwAssertNever(query);
  }
};
