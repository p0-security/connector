import { newZodResourceRootParsers } from "@p0security/connector";
import { z } from "zod";

import {
  baseRequestContext,
  listerQuery,
  listerResponse,
  userBody,
  userId,
} from "../common/definition.ts";

// A permission is the API's identifier, often a URL, and the permission's
// name. Both go into a request body only. The pair is the key, identical in
// a grant and a revoke.
const permission = {
  resourceServerIdentifier: z.string().min(1).max(600),
  permissionName: z.string().min(1).max(280),
};

// The permission to assign to the user directly. `null` takes back the
// request context's permission.
const policy = z.object(permission).nullable();

/** The permission P0 grants, which a revoke takes back. */
const requestContext = baseRequestContext.extend(permission);

export const schema = {
  userBody,
  userId,
  policy,
  listerQuery,
  listerResponse,
  requestContext,
};

export const spec = newZodResourceRootParsers(schema);
