import {
  type ResourceRootConnectorPrimitives,
  type ResourceRootRouter,
  type ResourceRootSchema,
  newZodResourceRootParsers,
} from "@p0security/connector-core";
import { z } from "zod";

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

type CustomConnectorSchema = ResourceRootSchema<
  z.infer<typeof UserBodySchema>,
  z.infer<typeof PolicySchema>,
  z.infer<typeof ListerQuerySchema>,
  z.infer<typeof RequestContextSchema>
>;

export type ConnectorPrimitives =
  ResourceRootConnectorPrimitives<CustomConnectorSchema>;

export type AccessRouter = ResourceRootRouter<CustomConnectorSchema>;

export const connectorParsers = newZodResourceRootParsers({
  userBody: UserBodySchema,
  userId: UserIdSchema,
  policy: PolicySchema,
  listerQuery: ListerQuerySchema,
  listerResponse: ListerResponseSchema,
  requestContext: RequestContextSchema,
});
