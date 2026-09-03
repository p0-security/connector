import {
  type ResourceRootSchema,
  newZodResourceRootParsers,
} from "@p0security/connector-core";
import { z } from "zod";

import type { CUSTOM_APP_ACCESS } from "./constants.ts";

export const UserBodySchema = z.object({ principal: z.string() }).strict();
export const UserIdSchema = z.string();
export const PolicySchema = z.string();
export const RequestContextSchema = z
  .object({ requestId: z.string(), appId: z.string() })
  .strict();
export const ListerQuerySchema = z
  .object({ type: z.literal("policy"), appId: z.string() })
  .strict();

const SelectOptionGroupSchema = z
  .object({ key: z.string(), value: z.string(), group: z.string() })
  .strict();
const SelectOptionSchema = z
  .object({ key: z.string(), value: z.string() })
  .strict();
const SelectItemSchema = z.union([SelectOptionGroupSchema, SelectOptionSchema]);
export const ListerResponseSchema = z.array(SelectItemSchema);

export type CustomAppAccessSchema = ResourceRootSchema<
  z.infer<typeof UserBodySchema>,
  z.infer<typeof PolicySchema>,
  z.infer<typeof ListerQuerySchema>,
  z.infer<typeof RequestContextSchema>
>;

export type CustomAppConnectorSchema = {
  [CUSTOM_APP_ACCESS]: CustomAppAccessSchema;
};

/**
 * The request body identifying the target user. Its `principal` is
 * the identity P0 knows the requester by - typically any email address
 * for a human requestor.
 */
export type UserBody = z.infer<typeof UserBodySchema>;

/**
 * The identifier the connector reports to P0 for a provisioned user. This
 * SDK always uses the principal itself.
 */
export type UserId = z.infer<typeof UserIdSchema>;

/**
 * A single policy. Each policy should represent a permission or
 * entitlement within a custom application.
 */
export type Policy = z.infer<typeof PolicySchema>;

/**
 * The per-request context every action receives. Includes the request
 * ID in P0 and the app ID.
 */
export type RequestContext = z.infer<typeof RequestContextSchema>;

/** The query `list` receives, in place of a {@link RequestContext}. */
export type ListerQuery = z.infer<typeof ListerQuerySchema>;

/** The catalogue returned by `list`, shown in the request-access picker. */
export type ListerResponse = z.infer<typeof ListerResponseSchema>;

/**
 * The actions a Custom Application connector implements.
 */
export type CustomAppConnectorActions = {
  /**
   * Checks if a user exists in the application. P0 calls this on every grant,
   * so it must be safe to call repeatedly and must not have side effects.
   *
   * @param context the request ID and application ID
   * @param user the user parameters, including the principal
   * @returns `true` if the user exists, `false` otherwise
   */
  userExists: (context: RequestContext, user: UserBody) => Promise<boolean>;

  /**
   * Creates a user in the application. The framework checks if the user exists
   * first using the `userExists` action before calling this function.
   *
   * @param context the request ID and application ID
   * @param user the user parameters, including the principal
   */
  createUser: (context: RequestContext, user: UserBody) => Promise<void>;

  /**
   * Deletes a specified user from the target system. If users cannot or should not
   * be deleted, this can be a no-op.
   *
   * @param context the request ID and application ID
   * @param user the user parameters, including the principal
   */
  deleteUser: (context: RequestContext, user: UserBody) => Promise<void>;

  /**
   * Applies the full set of policies on the user.
   *
   * This is a set, not a delta: `policies` is the complete list the user
   * should hold after the call, and an empty array revokes everything.
   *
   * @param context the request ID and application ID
   * @param user the user parameters, including the principal
   * @param policies all of the policies across all existing P0 grants for
   * this principal in this application
   */
  setPoliciesForUser: (
    context: RequestContext,
    user: UserBody,
    policies: Policy[]
  ) => Promise<void>;

  /**
   * Whether P0 may act on `user` — whose `principal` is the identity P0 knows
   * the requester by, typically their email address. Called by the SDK
   * internally before every other user-keyed action, which is why none of
   * those actions needs a check of its own. This action must not assume that
   * the user for this principal already exists in the application.
   *
   * @param context the request ID and application ID
   * @param user the user parameters, including the principal
   * @returns `true` allows the action, `false` refuses it. Validation can be opted-out
   * of by simply returning `true`.
   */
  validateUser: (context: RequestContext, user: UserBody) => Promise<boolean>;

  /**
   * Lists items in the application. Currently only supports one `type` ("policy").
   * The items returned may be a static catalog hard-coded into the action or they
   * may be based on dynamically fetched data in the application itself.
   *
   * Note the shape of the argument: `list` runs while someone is browsing for
   * access, not while a grant is being provisioned, so it receives a query
   * rather than a request context.
   *
   * @param query the type of query and the application ID
   * @returns a list of items (key, value, and optional grouping) to display
   * in a request modal dropdown
   */
  list: (query: ListerQuery) => Promise<ListerResponse>;
};

export const connectorParsers = newZodResourceRootParsers({
  userBody: UserBodySchema,
  userId: UserIdSchema,
  policy: PolicySchema,
  listerQuery: ListerQuerySchema,
  listerResponse: ListerResponseSchema,
  requestContext: RequestContextSchema,
});
