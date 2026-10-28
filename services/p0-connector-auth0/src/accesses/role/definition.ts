import { newZodResourceRootParsers } from "@p0security/connector-core";
import { z } from "zod";

import {
  auth0Id,
  baseRequestContext,
  listerQuery,
  listerResponse,
  userBody,
  userId,
} from "../common/definition.ts";

// The tenant role to assign to the user directly. `null` takes back the role
// P0 assigned, which the request context's policy names.
const policy = z.object({ roleId: auth0Id }).nullable();

/** The role P0 grants, which a revoke takes back. */
const requestContext = baseRequestContext.extend({ roleId: auth0Id });

export const schema = {
  userBody,
  userId,
  policy,
  listerQuery,
  listerResponse,
  requestContext,
};

export const spec = newZodResourceRootParsers(schema);
