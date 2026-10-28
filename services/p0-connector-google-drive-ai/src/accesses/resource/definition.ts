import { newZodResourceRootParsers } from "@p0security/connector-core";
import { z } from "zod";

// The grantee is the short-lived service account P0 mints for an agentic
// session, and a Drive ACL names a principal by address — so body and id are
// the same string, with nothing to translate between them. The address's shape
// is enforced in `validation` rather than here: the project half of the shape
// lives in the request context, which a parser for this member cannot see, and
// the framework's fold runs `validation` on every call without exception.
const userBody = z.string().min(1);
const userId = z.string().min(1);

// The grantee's one ACL entry on one item: `resourceId` is the folder or file
// inside the request's drive, and `role` what the entry should converge to,
// with `null` meaning no entry — which is how revocation is expressed, since
// the item has to be named even when nothing is left to grant on it.
//
// Two roles, deliberately not Drive's five. Everything above `writer` buys
// capabilities the agent's tool surface does not expose — trash, permanent
// delete, re-share — so granting them would widen the ACL with no matching
// capability.
const policy = z.object({
  resourceId: z.string().min(1),
  role: z.enum(["reader", "writer"]).nullable(),
});

// Lists every folder and file in one installed drive; the control plane does
// the matching and filtering.
const listerQuery = z.object({
  type: z.literal("resource"),
  context: z.object({ driveId: z.string().min(1) }),
});

const listerResponse = z
  .object({
    key: z.string(),
    value: z.string(),
    group: z.string().optional(),
  })
  .array();

// `driveId` is the installed shared drive the request was approved against;
// every item a call names must be inside it. `projectId` bounds the namespacing
// guard — it is the project this connector runs in, which is also the project
// P0 mints agentic identities in.
const requestContext = z.object({
  requestId: z.string(),
  driveId: z.string().min(1),
  projectId: z.string().min(1),
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
