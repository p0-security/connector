import { newZodUserProvisioningParsers } from "@p0security/connector";
import { z } from "zod";

export type CloudSqlEngine = "mysql" | "postgres";

type IdentityType = "service_account" | "user";

const identityTypeForEmail = (email: string): IdentityType =>
  email.endsWith(".gserviceaccount.com") ? "service_account" : "user";

const userBody = z.object({
  email: z.email().toLowerCase(),
});

const userId = z.string().min(1);

const requestContext = z.object({
  requestId: z.string(),
  gcp: z.object({
    projectId: z.string(), // target instance's project
    instanceId: z.string(),
    // MySQL is intentionally NOT accepted yet.
    engine: z.enum(["postgres"]).default("postgres"),
  }),
});

export const spec = newZodUserProvisioningParsers({
  userBody,
  userId,
  requestContext,
});

// identityType -> sqladmin user type (the auth method CloudSQL uses for the user)
const IAM_USER_TYPE: Record<IdentityType, string> = {
  user: "CLOUD_IAM_USER",
  service_account: "CLOUD_IAM_SERVICE_ACCOUNT",
} as const;

// identityType -> IAM member-string prefix consumed by member-verify
const MEMBER_PREFIX: Record<IdentityType, string> = {
  user: "user:",
  service_account: "serviceAccount:",
} as const;

// The IAM member string (e.g. `user:alice@p0.dev`) consumed by member-verify.
export const newMember = (email: string): string =>
  `${MEMBER_PREFIX[identityTypeForEmail(email)]}${email}`;

// The sqladmin user `type` (auth method) for the email's identity.
export const iamUserType = (email: string): string =>
  IAM_USER_TYPE[identityTypeForEmail(email)];
