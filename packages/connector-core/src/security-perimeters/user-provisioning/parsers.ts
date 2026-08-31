import type { JsonValue } from "type-fest";
import { z } from "zod";

import type { JSONParser, OneArgFuncParameter } from "../../parsers.ts";
import type { UserProvisioningSecurityPerimeter } from "./client.ts";
import type { UserProvisioningSchema } from "./schema.ts";

/**
 * Parsers to enforce type safety for UserProvisioning data and method inputs.
 *
 * @summary Parsers to enforce type safety for UserProvisioning data and method inputs.
 * @category High-Level
 */
export type UserProvisioningParsers<Schema extends UserProvisioningSchema> = {
  kind: "user-provisioning";
} & {
  [T in keyof Schema as Uncapitalize<T & string>]: JSONParser<Schema[T]>;
} & {
  [
    T in keyof UserProvisioningSecurityPerimeter<Schema> as Uncapitalize<
      T & string
    >
  ]: JSONParser<
    OneArgFuncParameter<UserProvisioningSecurityPerimeter<Schema>[T]>
  >;
};

/**
 * Creates {@link UserProvisioningParsers} from Zod schemas.
 *
 * @summary Creates {@link UserProvisioningParsers} from Zod schemas.
 * @category High-Level
 *
 * @example
 * const userBody = z.object({ email: z.email() });
 * const userId = z.string().min(1);
 * const requestContext = z.object({ requestId: z.string() });
 * const parsers = newZodUserProvisioningParsers({ userBody, userId, requestContext });
 */
export const newZodUserProvisioningParsers = <
  UserBodySchema extends z.ZodType<JsonValue>,
  UserIdSchema extends z.ZodType<string>,
  RequestContextSchema extends z.ZodType<JsonValue & { requestId: string }>,
>(schemas: {
  userBody: UserBodySchema;
  userId: UserIdSchema;
  requestContext: RequestContextSchema;
}): UserProvisioningParsers<{
  UserBody: z.output<UserBodySchema>;
  UserId: z.output<UserIdSchema>;
  RequestContext: z.output<RequestContextSchema>;
}> => {
  const { userBody, userId, requestContext } = schemas;
  const zodParser = <T extends Record<string, z.ZodType>>(obj: T) => {
    // `.required()` shouldn't be needed, but since a `z.ZodObject` can be
    // `.optional()` or `.nullable()`, it's a workaround. Longer term it'd be
    // better to constrain to a non-nullable object schema.
    return z.object(obj).required().parse;
  };
  // prettier-ignore
  return {
    kind: "user-provisioning",
    userBody: userBody.parse,
    userId: userId.parse,
    requestContext: requestContext.parse,
    identify: zodParser({ userBody, context: requestContext }),
    provision: zodParser({ userBody, context: requestContext }),
    deprovision: zodParser({ userId, context: requestContext }),
  };
};
