import { ConnectorError, type Logger } from "@p0security/connector";

import { requireAllowedDomains } from "../../allowed-domains.ts";
import type { Auth0Client } from "../../auth0/client.ts";
import { isNotFound } from "../../auth0/errors.ts";
import type { Auth0User } from "../../auth0/management.ts";

/** Who a call is for: the requestor's P0 email and the Auth0 user P0 found for it, in one tenant. */
export type Requestor = { tenant: string; email: string; userId: string };

// Each refusal is a `validation_error`, the type whose message P0 shows the
// requestor, and is only ever thrown before the connector has written
// anything.

export const refusal = ({
  reason,
  tenant,
  email,
  message,
  extra = {},
}: {
  reason: string;
  tenant: string;
  email: string;
  message: string;
  extra?: Record<string, string>;
}) =>
  new ConnectorError({
    type: "validation_error",
    message,
    payload: { reason, tenant, email, ...extra },
  });

export const requireAllowedEmail = (
  { tenant, email }: { tenant: string; email: string },
  log: Logger
) => {
  if (requireAllowedDomains().allows(email)) return;
  log.info({ tenant, email }, "refused an email outside the allowed domains");
  throw refusal({
    reason: "domain_not_allowed",
    tenant,
    email,
    message: `Your email domain isn't allowed for Auth0 tenant ${tenant}. Ask your P0 admin to check the connector's allowed domains.`,
  });
};

const isSameEmail = (auth0Email: string | undefined, email: string) =>
  auth0Email?.toLowerCase() === email.toLowerCase();

/**
 * The requestor's Auth0 user, once the email is in the allowed domains and
 * the user P0 found for it still has it.
 *
 * P0 sends both an email and a user id. The tie between them is what makes
 * the allowed domains mean something: without it an allowed email could be
 * paired with anyone's user id.
 */
export const requireRequestor = async (
  auth0: Auth0Client,
  log: Logger,
  requestor: Requestor
): Promise<Auth0User> => {
  const { tenant, email, userId } = requestor;
  requireAllowedEmail(requestor, log);
  const user = await auth0.getUser(userId).catch((error: unknown) => {
    if (isNotFound(error)) return null;
    throw error;
  });
  if (!user || !isSameEmail(user.email, email)) {
    log.warn(
      { tenant, userId, found: user !== null },
      "refused: the Auth0 user isn't the one P0 found for the email"
    );
    throw refusal({
      reason: "user_changed",
      tenant,
      email,
      message: `Your Auth0 user in ${tenant} changed after you requested access. Request access again.`,
      extra: { userId },
    });
  }
  return user;
};
