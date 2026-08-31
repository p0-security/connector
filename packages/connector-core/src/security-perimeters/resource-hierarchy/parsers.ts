import type { JsonValue } from "type-fest";
import { z } from "zod";

import type { SelectItem } from "../../listing/types.ts";
import type { JSONParser, OneArgFuncParameter } from "../../parsers.ts";
import type { ResourceHierarchySecurityPerimeter } from "./client.ts";
import type { ResourceHierarchySchema } from "./schema.ts";

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
export type ResourceHierarchyParsers<Schema extends ResourceHierarchySchema> = {
  kind: "resource-hierarchy";
} & {
  [T in keyof Schema as Uncapitalize<T & string>]: JSONParser<Schema[T]>;
} & {
  [
    T in keyof ResourceHierarchySecurityPerimeter<Schema> as Uncapitalize<
      T & string
    >
  ]: JSONParser<
    OneArgFuncParameter<ResourceHierarchySecurityPerimeter<Schema>[T]>
  >;
};

/**
 * Creates a ResourceHierarchyParsers using Zod schemas for parsing parameters and results.
 *
 * @summary Creates a ResourceHierarchyParsers from Zod schemas.
 * @category High-Level
 *
 * @typeParam UserBodySchema The Zod schema for the {@link ResourceHierarchySchema.UserBody}.
 * @typeParam UserIdSchema The Zod schema for the {@link ResourceHierarchySchema.UserId}.
 * @typeParam ResourceBodySchema The Zod schema for the {@link ResourceHierarchySchema.ResourceBody}.
 * @typeParam ResourceIdSchema The Zod schema for the {@link ResourceHierarchySchema.ResourceId}.
 *
 * @example
 *
 * ```ts
 * import { newZodResourceHierarchyParsers } from "@p0security/connector-core";
 * import { z } from "zod";
 *
 * export const rdsParsers = newZodResourceHierarchyParsers({
 *   userBody: z.object({ username: z.string().min(1) }),
 *   userId: z.string().min(1),
 *   resourceBody: z.string().min(1),
 *   resourceId: z.string().min(1),
 *   policy: z.object({ action: z.string() }),
 *   listerQuery: z.object({ type: z.string() }),
 *   listerResponse: z.array(z.object({ key: z.string(), value: z.string() })),
 *   requestContext: z.object({ requestId: z.string() }),
 * });
 *
 * ```
 */
export const newZodResourceHierarchyParsers = <
  UserBodySchema extends z.ZodType<JsonValue>,
  UserIdSchema extends z.ZodType<string>,
  ResourceBodySchema extends z.ZodType<string>,
  PolicySchema extends z.ZodType<JsonValue>,
  ResourceIdSchema extends z.ZodType<string>,
  ListerQuerySchema extends z.ZodType<JsonValue & { type: string }>,
  ListerResponseSchema extends z.ZodType<SelectItem[]>,
  RequestContextSchema extends z.ZodType<JsonValue & { requestId: string }>,
>(schemas: {
  userBody: UserBodySchema;
  userId: UserIdSchema;
  resourceBody: ResourceBodySchema;
  policy: PolicySchema;
  resourceId: ResourceIdSchema;
  listerQuery: ListerQuerySchema;
  listerResponse: ListerResponseSchema;
  requestContext: RequestContextSchema;
}): ResourceHierarchyParsers<{
  UserBody: z.output<UserBodySchema>;
  UserId: z.output<UserIdSchema>;
  ResourceBody: z.output<ResourceBodySchema>;
  Policy: z.output<PolicySchema>;
  ResourceId: z.output<ResourceIdSchema>;
  ListerQuery: z.output<ListerQuerySchema>;
  ListerResponse: z.output<ListerResponseSchema>;
  RequestContext: z.output<RequestContextSchema>;
}> => {
  const {
    userBody,
    userId,
    resourceBody,
    policy,
    resourceId,
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
    kind: "resource-hierarchy",
    userBody: userBody.parse,
    userId: userId.parse,
    resourceBody: resourceBody.parse,
    resourceId: resourceId.parse,
    policy: policy.parse,
    listerQuery: listerQuery.parse,
    listerResponse: listerResponse.parse,
    requestContext: requestContext.parse,
    identifyUser: zodParser({ userBody, context: requestContext }),
    provisionUser: zodParser({ userBody, context: requestContext }),
    addPoliciesToResource: zodParser({ resourceId, policies: z.array(policy), context: requestContext }),
    removePoliciesFromResource: zodParser({ resourceId, policies: z.array(policy), context: requestContext }),
    createAccessResource: zodParser({ resourceBody, context: requestContext }),
    deleteAccessResource: zodParser({ resourceId, context: requestContext }),
    bindAccessResource: zodParser({ userId, resourceId, context: requestContext }),
    unbindAccessResource: zodParser({ userId, resourceId, context: requestContext }),
    list: zodParser({ query: listerQuery }),
  };
};
