import type { JsonValue } from "type-fest";
import { z } from "zod";

import type { SelectItem } from "../../listing/types.ts";
import type { JSONParser, OneArgFuncParameter } from "../../parsers.ts";
import type { ResourceRootSecurityPerimeter } from "./client.ts";
import type { ResourceRootSchema } from "./schema.ts";

/**
 * Parsers to enforce type safety for a {@link ConnectorSpec}.
 *
 * These parsers are the root of the type system for a {@link ConnectorSpec},
 * ensuring that all data flowing through the {@link ConnectorSpec} adheres to the expected types.
 *
 * @summary Parsers to enforce type safety for a {@link ConnectorSpec}.
 * @category High-Level
 * @expandType ConnectorSchemaParsers
 * @expandType ConnectorClientArgParsers
 * @inlineType ConnectorSchemaParsers
 * @inlineType ConnectorClientArgParsers
 */
export type ResourceRootParsers<Schema extends ResourceRootSchema> = {
  kind: "resource-root";
} & {
  [T in keyof Schema as Uncapitalize<T & string>]: JSONParser<Schema[T]>;
} & {
  [
    T in keyof ResourceRootSecurityPerimeter<Schema> as Uncapitalize<T & string>
  ]: JSONParser<OneArgFuncParameter<ResourceRootSecurityPerimeter<Schema>[T]>>;
};

/**
 * Creates a ResourceRootParsers using Zod schemas for parsing parameters and results.
 *
 * @summary Creates a ResourceRootParsers from Zod schemas.
 * @category High-Level
 *
 * @typeParam UserBodySchema The Zod schema for the {@link ResourceRootSchema.UserBody}.
 * @typeParam UserIdSchema The Zod schema for the {@link ResourceRootSchema.UserId}.
 */
export const newZodResourceRootParsers = <
  UserBodySchema extends z.ZodType<JsonValue>,
  UserIdSchema extends z.ZodType<string>,
  PolicySchema extends z.ZodType<JsonValue>,
  ListerQuerySchema extends z.ZodType<JsonValue & { type: string }>,
  ListerResponseSchema extends z.ZodType<SelectItem[]>,
  RequestContextSchema extends z.ZodType<JsonValue & { requestId: string }>,
>(schemas: {
  userBody: UserBodySchema;
  userId: UserIdSchema;
  policy: PolicySchema;
  listerQuery: ListerQuerySchema;
  listerResponse: ListerResponseSchema;
  requestContext: RequestContextSchema;
}): ResourceRootParsers<{
  UserBody: z.output<UserBodySchema>;
  UserId: z.output<UserIdSchema>;
  Policy: z.output<PolicySchema>;
  ListerQuery: z.output<ListerQuerySchema>;
  ListerResponse: z.output<ListerResponseSchema>;
  RequestContext: z.output<RequestContextSchema>;
}> => {
  const {
    userBody,
    userId,
    policy,
    listerQuery,
    listerResponse,
    requestContext,
  } = schemas;
  const zodParser = <T extends Record<string, z.ZodType>>(obj: T) => {
    // Shouldn't "need" `.required()`, but since the `z.ZodObject` can be `.optional()` or `.nullable()`,
    // it's needed as a work around. It'd be better to figure out how to `extends z.NonNullable<z.ZodObject>`
    // long term
    return z.object(obj).required().parse;
  };
  // prettier-ignore
  return {
    kind: "resource-root",
    userBody: userBody.parse,
    userId: userId.parse,
    policy: policy.parse,
    listerQuery: listerQuery.parse,
    listerResponse: listerResponse.parse,
    requestContext: requestContext.parse,
    identifyUser: zodParser({ userBody, context: requestContext }),
    provisionUser: zodParser({ userBody, context: requestContext }),
    deleteUser: zodParser({ userId, context: requestContext }),
    setPoliciesForUser: zodParser({ userId, policies: z.array(policy), context: requestContext }),
    list: zodParser({ query: listerQuery }),
  };
};
