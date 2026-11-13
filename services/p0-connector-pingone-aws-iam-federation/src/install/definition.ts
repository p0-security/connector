import { z } from "zod";

export const ROLE_ATTRIBUTE = "https://aws.amazon.com/SAML/Attributes/Role";

export const SOURCE_IDENTITY_ATTRIBUTE =
  "https://aws.amazon.com/SAML/Attributes/SourceIdentity";

export const URI_NAME_FORMAT =
  "urn:oasis:names:tc:SAML:2.0:attrname-format:uri";

export const PERSISTENT_NAME_ID_FORMAT =
  "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent";

/**
 * What install validation returns once every check has passed. A failed
 * check is thrown, with its name in `payload.step`.
 */
export const installValidation = z.object({
  /** The app's name in the PingOne admin console. */
  name: z.string(),
  /** The entity ID in the app's SAML metadata. The AWS SAML provider must have the same one. */
  entityId: z.string().min(1),
});

export type InstallValidation = z.infer<typeof installValidation>;
