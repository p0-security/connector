import type { Logger } from "@p0security/connector";

import { requireAllowedDomains } from "../../allowed-domains.ts";
import type { CloudClient, Member } from "../../cloud/client.ts";
import { refusal } from "../../refusals.ts";

/**
 * Refuses, as `domain_not_allowed`, an email whose domain
 * `DOMAIN_ALLOW_PATTERN` doesn't allow. Called before any ClickHouse Cloud
 * call, so the connector never looks up someone it doesn't act for.
 */
export const requireAllowedEmail = (email: string, log: Logger): void => {
  if (requireAllowedDomains().allows(email)) return;
  log.info("the email's domain isn't allowed");
  throw refusal({
    reason: "domain_not_allowed",
    message: `P0 doesn't act for ${email}: the email's domain isn't one the connector's DOMAIN_ALLOW_PATTERN allows.`,
    payload: { email },
  });
};

/**
 * The organization's member with the email, ignoring case, or `undefined`
 * when there's none. More than one is refused as `ambiguous_member`. Failures
 * from ClickHouse Cloud are thrown as they are, for the caller to map.
 */
export const findMember = async (
  cloud: CloudClient,
  { organizationId, email }: { organizationId: string; email: string }
): Promise<Member | undefined> => {
  const wanted = email.toLowerCase();
  const members = (await cloud.listMembers()).filter(
    (member) => member.email?.toLowerCase() === wanted
  );
  const [only, ...others] = members;
  if (others.length > 0) {
    throw refusal({
      reason: "ambiguous_member",
      message: `${members.length} members of the ClickHouse Cloud organization ${organizationId} have the email ${email}, so P0 can't tell which is the requestor. Ask a ClickHouse Cloud admin to remove the extra member.`,
      payload: { email, members: members.length },
    });
  }
  return only;
};
