import { z } from "zod";

/**
 * What install validation returns once every check has passed. A failed
 * check is thrown, with its name in `payload.step`.
 */
export const installValidation = z.object({
  /** The entity ID in PingFederate's SAML metadata. The AWS SAML provider must have the same one. */
  entityId: z.string().min(1),
});

export type InstallValidation = z.infer<typeof installValidation>;
