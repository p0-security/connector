import { z } from "zod";

/** Okta's name for the AWS Account Federation app in its catalog. */
export const AWS_APP_NAME = "amazon_aws";

/** The app user property that marks an assignment P0 made. */
export const MANAGED_BY_P0 = {
  managedByP0: { scope: "NONE", title: "Managed by P0", type: "boolean" },
} as const;

/**
 * What install validation returns once every check has passed. A failed
 * check is thrown, with its name in `payload.step`.
 */
export const installValidation = z.object({
  /** The app's label in the Okta Admin Console. */
  label: z.string(),
  /** The entity ID in the app's SAML metadata. The AWS SAML provider must have the same one. */
  entityId: z.string().min(1),
});

export type InstallValidation = z.infer<typeof installValidation>;
