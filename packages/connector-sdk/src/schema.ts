import {
  type ResourceRootConnectorPrimitives,
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
 * The request body identifying the target user, as `getUser` and `createUser`
 * receive it. Its `principal` is the identity P0 knows the requester by -
 * typically any email address for a human requestor.
 */
export type UserBody = z.infer<typeof UserBodySchema>;

/**
 * This application's own identifier for a user: the exact string a previous
 * `getUser` or `createUser` returned. A database role name, a numeric id, a
 * directory DN, or the principal itself, if that is how the application
 * names its accounts.
 */
export type UserId = z.infer<typeof UserIdSchema>;

/**
 * A single policy. Each policy should represent a permission or
 * entitlement within a custom application.
 */
export type Policy = z.infer<typeof PolicySchema>;

/** The per-request context every action receives. */
export type RequestContext = z.infer<typeof RequestContextSchema>;

/** The query `list` receives. */
export type ListerQuery = z.infer<typeof ListerQuerySchema>;

/** The catalogue returned by `list`, shown in the request-access picker. */
export type ListerResponse = z.infer<typeof ListerResponseSchema>;

/**
 * The actions a Custom Application connector implements.
 */
export type CustomAppConnectorActions = Omit<
  ResourceRootConnectorPrimitives<CustomAppAccessSchema>,
  "validation"
> & {
  /**
   * Whether P0 may act on `principal` — the identity P0 knows the requester
   * by (typically their email address). Called by the SDK internally before
   * invoking the `getUser` and `createUser` actions.
   *
   * `true` allows the action, `false` refuses it. Validation can be opted-out
   * of by simply returning `true`.
   *
   * This action must not assume that the user for this principal already
   * exists in the application.
   *
   * @group User
   */
  validatePrincipal: (
    context: RequestContext,
    principal: UserBody["principal"]
  ) => Promise<boolean>;

  /**
   * Whether P0 may act on `userId` — this application's own identifier for the
   * user, as `getUser` or `createUser` returned it. Called by the SDK internally
   * before invoking the `deleteUser` and `setPoliciesForUser` actions.
   *
   * `true` allows the action, `false` refuses it. Validation can be opted-out
   * of by simply returning `true`.
   *
   * P0 will invoke this validator at a point where the user is already expected to
   * exist in the application. If this validator queries the application as part of
   * its implementation but the user cannot be found, throw a `ConnectorError`.
   *
   * @group User
   */
  validateUserId: (context: RequestContext, userId: UserId) => Promise<boolean>;
};

export const connectorParsers = newZodResourceRootParsers({
  userBody: UserBodySchema,
  userId: UserIdSchema,
  policy: PolicySchema,
  listerQuery: ListerQuerySchema,
  listerResponse: ListerResponseSchema,
  requestContext: RequestContextSchema,
});
