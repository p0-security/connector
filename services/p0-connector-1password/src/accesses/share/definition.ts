import { newZodResourceRootParsers } from "@p0security/connector-core";
import { z } from "zod";

// 1Password's IDs for vaults and items: 26 lowercase letters and digits, the
// base32 form 1Password gives each. Not UUIDs.
const ONEPASSWORD_ID = /^[a-z0-9]{26}$/;

export const vaultId = z
  .string()
  .regex(ONEPASSWORD_ID, "must be a 1Password vault ID");

export const itemId = z
  .string()
  .regex(ONEPASSWORD_ID, "must be a 1Password item ID");

const email = z.email();

// Where the account's service account token is, in the customer's own secret
// manager. A pointer, never the token: the connector reads it itself.
const tokenSecret = z.discriminatedUnion("manager", [
  z.object({
    manager: z.literal("aws"),
    secretId: z.string().min(1),
    region: z.string().min(1),
  }),
  z.object({
    manager: z.literal("gcp"),
    secretId: z.string().min(1),
    projectId: z.string().min(1),
  }),
]);

export type TokenSecret = z.infer<typeof tokenSecret>;

/** What the connector needs to act for one 1Password account: where its
 * service account's token is. The vaults are whichever the service account
 * can see. */
export const accountCredentials = z.object({ tokenSecret });

export type AccountCredentials = z.infer<typeof accountCredentials>;

/** What the connector needs to act on one 1Password vault. */
export const vaultCredentials = accountCredentials.extend({ vault: vaultId });

export type VaultCredentials = z.infer<typeof vaultCredentials>;

// The requestor's P0 email is the only identity the connector takes.
const userBody = email;
const userId = email;

// Nothing to set: a share is made at stage, and the grant and the revoke do
// nothing (see the handler).
const policy = z.object({});

const requestContext = vaultCredentials.extend({ requestId: z.string() });

// `list` gets no request context, so each query carries the credentials, as
// its `context`.
//
// - `vaults` lists the vaults the service account can see, as `{ key: <vault
//   id>, value: <title> }`. Its context has no vault.
// - `items` lists the vault's active items as `{ key: <item id>, value:
//   <title>, group: <category> }`, such as `Login`. Never a field's value.
// - `sharing-policy` reads the account's item sharing policy, which 1Password
//   reads through an item. One answer per field, each `{ key: <field>, value:
//   <value> }`: `maxExpiry` and `defaultExpiry` (such as `SevenDays`), and
//   `allowedRecipientTypes` and `allowedTypes`, comma-joined (such as
//   `Email,Domain`).
const listerQuery = z.discriminatedUnion("type", [
  z.object({ type: z.literal("vaults"), context: accountCredentials }),
  z.object({ type: z.literal("items"), context: vaultCredentials }),
  z.object({
    type: z.literal("sharing-policy"),
    context: vaultCredentials,
    itemId,
  }),
]);

const listerResponse = z
  .object({
    key: z.string(),
    value: z.string(),
    group: z.string().optional(),
  })
  .array();

export const schema = {
  userBody,
  userId,
  policy,
  listerQuery,
  listerResponse,
  requestContext,
};

export const spec = newZodResourceRootParsers(schema);
