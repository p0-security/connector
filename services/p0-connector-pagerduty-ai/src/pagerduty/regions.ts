/** PagerDuty service regions. Each is the region in the
 * `as_account-<region>.<subdomain>` scope. */
export const pagerdutyRegions = ["us", "eu"] as const;

export type PagerdutyRegion = (typeof pagerdutyRegions)[number];
