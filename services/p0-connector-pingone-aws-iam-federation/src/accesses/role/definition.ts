import { newZodResourceHierarchyParsers } from "@p0security/connector-core";
import { z } from "zod";

import { app } from "../../account.ts";

/** The user's email in PingOne. */
const userBody = z.email();

/** PingOne's ID for the user. */
const userId = z.string().min(1);

/** A role attribute value, `role ARN,provider ARN`, as P0 makes it. The resource's ID is the label too. */
const role = z.string().min(1);

/** A role label carries no policies. */
const policy = z.null();

/** The connector lists nothing: P0 lists the roles from AWS. */
const listerQuery = z.object({ type: z.literal("role"), context: app });

const listerResponse = z
  .object({ key: z.string(), value: z.string(), group: z.string().optional() })
  .array();

const requestContext = z.object({ requestId: z.string(), ...app.shape });

export const schema = {
  userBody,
  userId,
  resourceBody: role,
  resourceId: role,
  policy,
  listerQuery,
  listerResponse,
  requestContext,
};

export const spec = newZodResourceHierarchyParsers(schema);
