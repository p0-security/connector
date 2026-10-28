import { z } from "zod";

/**
 * A ClickHouse Cloud ID: an organization's, a service's, a role's or a Query
 * API endpoint's. The Cloud API's own pattern for one, without the all-zero
 * ID. Each becomes a URL path segment, so nothing but hex digits and dashes
 * gets in.
 */
export const CLOUD_ID_PATTERN =
  /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-8][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$/;

/** The organization ID's message, for the app and the provider to copy. */
export const ORGANIZATION_ID_MESSAGE =
  "must be the ClickHouse Cloud organization ID, a UUID such as 0b5a3c1e-6f2d-4e8a-9c7b-1d2e3f4a5b6c";

export const organizationId = z
  .string()
  .regex(CLOUD_ID_PATTERN, ORGANIZATION_ID_MESSAGE);

export const serviceId = z
  .string()
  .regex(CLOUD_ID_PATTERN, "must be a ClickHouse Cloud service ID, a UUID");

/**
 * Where the API key is, in the customer's own secret manager. A pointer,
 * never the key: the connector reads it itself.
 */
export const secretPointer = z.discriminatedUnion("manager", [
  z.object({
    manager: z.literal("aws"),
    secretId: z.string().min(1),
    region: z.string().min(1),
  }),
  z.object({
    manager: z.literal("gcp"),
    secretId: z.string().min(1),
    projectId: z.string().min(1),
  }),
]);

export type SecretPointer = z.infer<typeof secretPointer>;

/**
 * What the connector needs to act on one ClickHouse Cloud organization: its
 * ID, and where the organization's API key is. Every request context and
 * every lister query carries it.
 */
export const organizationCredentials = z.object({
  organizationId,
  apiKeySecret: secretPointer,
});

export type OrganizationCredentials = z.infer<typeof organizationCredentials>;
