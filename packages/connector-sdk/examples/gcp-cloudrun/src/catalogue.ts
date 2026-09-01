import type { ListerResponse, Policy } from "@p0security/connector-sdk";

/**
 * The entitlements this application exposes, as P0's request-access picker
 * shows them.
 *
 * `key` is what comes back to `setPoliciesForUser`, so it must be the
 * identifier your application actually understands. `value` is the label a
 * requester reads, and the optional `group` buckets related entitlements in
 * the picker.
 *
 * A static list keeps the example readable. A real connector would fetch this
 * from the target system inside `list`.
 */
export const POLICY_CATALOGUE: ListerResponse = [
  {
    key: "billing.invoices.read",
    value: "Read invoices",
    group: "Billing",
  },
  {
    key: "billing.invoices.write",
    value: "Create and void invoices",
    group: "Billing",
  },
  {
    key: "billing.refunds.approve",
    value: "Approve refunds",
    group: "Billing",
  },
  {
    key: "reports.export",
    value: "Export reports",
    group: "Reporting",
  },
  {
    key: "admin.settings.write",
    value: "Change application settings",
    group: "Administration",
  },
];

const KNOWN_POLICY_KEYS = new Set(POLICY_CATALOGUE.map(({ key }) => key));

/**
 * Whether a policy P0 sent is one this application recognizes.
 *
 * Worth checking even though P0 only sends back keys `list` handed it: the
 * catalogue can change between the moment a requester picks an entitlement and
 * the moment the grant is provisioned.
 */
export const isKnownPolicy = (policy: Policy): boolean =>
  KNOWN_POLICY_KEYS.has(policy);
