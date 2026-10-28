import type { ItemShareDuration } from "@1password/sdk";
import {
  type AnyConnectorTRPCInstance,
  ConnectorError,
  type Logger,
  withRouteLogging,
} from "@p0security/connector";

import type { TokenSecret } from "../accesses/share/definition.ts";
import { requireAllowedDomains } from "../allowed-domains.ts";
import { type OnePasswordClient, newOnePasswordClient } from "../client.ts";
import { toConnectorError } from "../onepassword/errors.ts";
import { allowsSharingByEmail } from "../onepassword/policy.ts";
import { refusal } from "../refusals.ts";
import {
  SHARE_DURATIONS,
  type ShareDuration,
  type ShareInput,
  type ShareOutput,
  shareInput,
} from "./definition.ts";

const HOUR_MS = 60 * 60 * 1000;
const DAY_MS = 24 * HOUR_MS;

/** How long each of 1Password's options lasts. */
const DURATION_MS: Record<ShareDuration, number> = {
  OneHour: HOUR_MS,
  OneDay: DAY_MS,
  SevenDays: 7 * DAY_MS,
  FourteenDays: 14 * DAY_MS,
  ThirtyDays: 30 * DAY_MS,
};

/**
 * Whether `duration` is no longer than `max`. 1Password's durations are
 * strings with no order of their own, so they are ranked by their place in
 * {@link SHARE_DURATIONS}. A `max` the connector doesn't know allows none.
 */
export const isWithin = (duration: ShareDuration, max: string): boolean => {
  const allowed = SHARE_DURATIONS.findIndex((known) => known === max);
  return allowed >= 0 && SHARE_DURATIONS.indexOf(duration) <= allowed;
};

// The SDK's durations are a string enum, which can't be imported for its
// values (see `client.ts`). This fails to compile unless its strings are
// exactly the connector's, which makes the cast in `toSdkDuration` safe.
type SameStrings<A extends string, B extends string> = [A] extends [B]
  ? [B] extends [A]
    ? true
    : false
  : false;
const SDK_DURATIONS_MATCH: SameStrings<`${ItemShareDuration}`, ShareDuration> =
  true;
void SDK_DURATIONS_MATCH;

const toSdkDuration = (duration: ShareDuration) =>
  duration as ItemShareDuration;

export type ShareDependencies = {
  connect: (tokenSecret: TokenSecret) => Promise<OnePasswordClient>;
  logger: Logger;
  now: () => number;
};

/**
 * Makes a read-only share link to one item, for one email, that 1Password
 * expires after `expireAfter`. In order:
 *
 * 1. The email's domain is one `DOMAIN_ALLOW_PATTERN` allows.
 * 2. The account's sharing policy allows sharing with a person by email, for
 *    that long.
 * 3. 1Password validates the email as the only recipient. A share without
 *    recipients would be a public link, which the connector never makes.
 * 4. The item, which carries its field values: it goes to `create` and
 *    nowhere else, and is read only once every check has passed.
 * 5. The link, which opens only once when `oneTimeOnly` says so.
 *
 * It isn't retried: 1Password can't list or delete a share, so a retry would
 * make a second link. The link is never logged or put in an error.
 */
export const createShare = async (
  { vault, tokenSecret, itemId, email, expireAfter, oneTimeOnly }: ShareInput,
  { connect, logger, now }: ShareDependencies
): Promise<ShareOutput> => {
  if (!requireAllowedDomains().allows(email)) {
    logger.info(
      { vault, email },
      "refused an email outside the allowed domains"
    );
    throw refusal({
      reason: "domain_not_allowed",
      message: `Your email domain isn't allowed for the 1Password vault ${vault}. Ask your P0 admin to check the connector's allowed domains.`,
      payload: { vault, email },
    });
  }
  const askedAt = now();
  try {
    const client = await connect(tokenSecret);
    const policy = await client.items.shares.getAccountPolicy(vault, itemId);
    if (!allowsSharingByEmail(policy)) {
      throw refusal({
        reason: "sharing_policy",
        message:
          "1Password's item sharing policy doesn't allow sharing an item with a specific person by email. Ask a 1Password owner or administrator to allow it.",
        payload: { vault, itemId },
      });
    }
    if (!isWithin(expireAfter, policy.maxExpiry)) {
      throw refusal({
        reason: "sharing_policy",
        message: `1Password's item sharing policy allows links that last up to ${policy.maxExpiry}, shorter than the ${expireAfter} requested. Request a shorter duration, or ask a 1Password owner or administrator to allow longer links.`,
        payload: { vault, itemId, expireAfter, maxExpiry: policy.maxExpiry },
      });
    }
    const recipients = await client.items.shares.validateRecipients(policy, [
      email,
    ]);
    const [recipient, ...others] = recipients;
    // 1Password hands the email back lowercased (checked against a real
    // account, INT-547), so only its case may differ.
    if (
      recipient?.type !== "Email" ||
      recipient.parameters.email.toLowerCase() !== email.toLowerCase() ||
      others.length > 0
    ) {
      throw new ConnectorError({
        type: "validation_error",
        message: `1Password won't share an item with ${email} alone. Check that 1Password's item sharing policy allows sharing with this email.`,
        payload: { vault, itemId, email, recipients: recipients.length },
      });
    }
    // Read last, so a refused share never loads the item's field values.
    const item = await client.items.get(vault, itemId);
    const link = await client.items.shares.create(item, policy, {
      recipients,
      expireAfter: toSdkDuration(expireAfter),
      oneTimeOnly,
    });
    logger.info(
      { vault, itemId, email, expireAfter, oneTimeOnly },
      "shared the item"
    );
    return {
      link,
      expiresAt: new Date(askedAt + DURATION_MS[expireAfter]).toISOString(),
      oneTimeOnly,
    };
  } catch (error) {
    throw toConnectorError(error, { vault, itemId });
  }
};

/**
 * The share route, `share.create`. P0 calls it once per approved request, at
 * stage. The framework's connector router has no slot for a route of an
 * integration's own, so it sits in the install router, as install validation
 * does.
 */
export const router = (t: AnyConnectorTRPCInstance) => {
  const { router } = t;
  // Logs each call and its failure, never its input or its answer.
  const procedure = withRouteLogging(t.procedure);

  return router({
    create: procedure.input(shareInput.parse).mutation(({ input, ctx }) =>
      createShare(input, {
        connect: newOnePasswordClient,
        logger: ctx.logger.child({ vault: input.vault }),
        now: Date.now,
      })
    ),
  });
};
