import { newZodResourceRootParsers } from "@p0security/connector-core";
import { z } from "zod";

/** The service account to find or create, and the federated subject it stands
 * for. Everything `createUser` needs is here; the perimeter's namespacing
 * guards re-check each field's shape. */
const userBody = z.object({
  project: z.string(),
  accountId: z.string(),
  subject: z.string(),
});

/** A service account email address. */
const userId = z.string().min(1);

/** Who may impersonate the identity, and until when. */
const policy = z.object({
  member: z.string().min(1),
  expiresAt: z.iso.datetime({ offset: true }).optional(),
});

// Listing is refused by this connector, but the framework mounts the endpoint
// unconditionally, so the query still needs a shape.
const listerQuery = z.object({
  type: z.literal("unsupported"),
});

const listerResponse = z
  .object({
    key: z.string(),
    value: z.string(),
    group: z.string().optional(),
  })
  .array();

/** `project` is what the id-keyed calls (delete, converge) check an address
 * against: they are handed a user id, never a body. */
const requestContext = z.object({
  requestId: z.string(),
  project: z.string(),
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
