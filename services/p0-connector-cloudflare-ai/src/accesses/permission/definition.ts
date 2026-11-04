import { newZodResourceRootParsers } from "@p0security/connector-core";
import { z } from "zod";

import { account } from "../../account.ts";

const userBody = z.string().min(1);
const userId = z.string().min(1);

/** Cloudflare permission group ids. */
const groups = z.array(z.string().min(1)).min(1);

/** Where a policy grants its groups: the account, one zone by name, or every zone. */
export const resource = z.discriminatedUnion("scope", [
  z.object({ scope: z.literal("account"), groups }),
  z.object({ scope: z.literal("all-zones"), groups }),
  z.object({ scope: z.literal("zone"), zone: z.string().min(1), groups }),
]);

export type Resource = z.infer<typeof resource>;

// The control plane merges every open request into this one policy. When the
// last request leaves, it sends no resources and no expiry.
const policy = z.union([
  z.object({
    /** ISO 8601 in UTC, in whole seconds. */
    expiresOn: z.iso.datetime({ precision: 0 }),
    resources: z.array(resource).min(1),
  }),
  z.object({ resources: z.tuple([]) }),
]);

export type Policy = z.infer<typeof policy>;

/** Where a permission group applies. Zone groups serve one zone and all zones. */
const groupScope = z.enum(["account", "zone"]);

export type GroupScope = z.infer<typeof groupScope>;

/**
 * - `policies`: the groups an agent can request on `scope`, by id.
 * - `zone`: `*` for all zones, then each of the account's zones, by name.
 */
const listerQuery = z.discriminatedUnion("type", [
  z.object({
    type: z.literal("policies"),
    scope: groupScope,
    context: account,
  }),
  z.object({ type: z.literal("zone"), context: account }),
]);

export type ListerQuery = z.infer<typeof listerQuery>;

const listerResponse = z
  .object({
    key: z.string(),
    value: z.string(),
    group: z.string().optional(),
  })
  .array();

export type ListerResponse = z.infer<typeof listerResponse>;

const requestContext = z.object({
  requestId: z.string(),
  ...account.shape,
});

export const schema = {
  userBody,
  userId,
  policy,
  listerQuery,
  listerResponse,
  requestContext,
};

export const spec = newZodResourceRootParsers(schema);
