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
 * The actions a Custom Application connector implements.
 */
export type CustomAppConnectorActions = Omit<
  ResourceRootConnectorPrimitives<CustomAppAccessSchema>,
  "validation"
>;

/**
 * The request body identifying the target user, as `getUser` and `createUser`
 * receive it.
 */
export type UserBody = z.infer<typeof UserBodySchema>;

/** The application's own identifier for a user — whatever `getUser`/`createUser` returned. */
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

export const connectorParsers = newZodResourceRootParsers({
  userBody: UserBodySchema,
  userId: UserIdSchema,
  policy: PolicySchema,
  listerQuery: ListerQuerySchema,
  listerResponse: ListerResponseSchema,
  requestContext: RequestContextSchema,
});
