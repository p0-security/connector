import type { ItemShareAccountPolicy } from "@1password/sdk";

/** Whether `values` holds `value`: the SDK's string enums, read as strings. */
const has = (values: readonly string[], value: string) =>
  values.includes(value);

/**
 * Whether the account's sharing policy lets a share go to one person, by
 * email: it allows links for specific people (`Authenticated`, not only
 * public ones), and email recipients (not only domains).
 */
export const allowsSharingByEmail = (
  policy: Pick<ItemShareAccountPolicy, "allowedRecipientTypes" | "allowedTypes">
) =>
  has(policy.allowedTypes, "Authenticated") &&
  has(policy.allowedRecipientTypes, "Email");
