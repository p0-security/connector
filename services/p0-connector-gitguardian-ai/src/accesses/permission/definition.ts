import { newZodResourceRootParsers } from "@p0security/connector-core";
import { z } from "zod";

import {
  adminTokenSecret,
  region,
  workspaceId,
} from "../../secret-location.ts";

/**
 * The scopes a grant may hold. The app refuses others too; the connector
 * checks again so that no caller can mint a scope such as `api_tokens:write`.
 */
export const requestableScopes = [
  "scan",
  "incidents:read",
  "incidents:write",
  "sources:read",
  "members:read",
] as const;

/** The grant's secret name. */
const userBody = z.string().min(1);
/** The grant secret's ref. */
const userId = z.string().min(1);

// The control plane merges every open request's scopes into this one policy.
// It sends no scopes when it revokes the last request. Any string is accepted
// here, so that a scope outside `requestableScopes` gets a readable refusal
// instead of a parse error.
const policy = z.object({
  scopes: z.array(z.string().min(1)),
});

const workspace = {
  region,
  workspaceId,
  secrets: adminTokenSecret,
};

const listerQuery = z.object({
  type: z.literal("scope"),
  context: z.object(workspace),
});

const listerResponse = z
  .object({
    key: z.string(),
    value: z.string(),
    group: z.string().optional(),
  })
  .array();

const requestContext = z.object({
  requestId: z.string(),
  ...workspace,
  /**
   * When the requester's longest open grant in this workspace ends, or `null`
   * when one of them has no end. The connector turns it into the token's
   * lifetime.
   */
  grantEndsAt: z.iso.datetime({ offset: true }).nullable(),
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
