import { z } from "zod";

import { organizationCredentials } from "../credentials.ts";

/** What P0 sends to validate an install: the organization's credentials. */
export const installInput = organizationCredentials;

/**
 * Where one service stands after the install:
 *
 * - `ready`: every kind of access can be requested on it.
 * - `console-only`: only `console` access can be, because its ClickHouse is
 *   older than 26.4.
 * - `not-ready`: nothing can be, and `reason` says why.
 */
export const serviceReport = z.union([
  z.object({ id: z.string(), name: z.string(), status: z.literal("ready") }),
  z.object({
    id: z.string(),
    name: z.string(),
    status: z.enum(["console-only", "not-ready"]),
    reason: z.string(),
  }),
]);

export type ServiceReport = z.infer<typeof serviceReport>;

/**
 * What install validation returns for an organization once every check has
 * passed, which means at least one service is ready or console-only. A failed check is
 * thrown with its name in `payload.step`, so these are facts about an
 * install that works, not results to inspect.
 */
export const installValidation = z.object({
  /** The organization's name in ClickHouse Cloud. */
  organizationName: z.string(),
  /** The API key's ID, from the secret. Not a secret. */
  apiKeyId: z.string(),
  /**
   * The API key's UUID among the organization's keys, which P0's endpoints'
   * `apiKeyIds` take. Not the key ID.
   */
  apiKeyUuid: z.string(),
  /** The connector's `DOMAIN_ALLOW_PATTERN` as deployed, for the install to display. */
  allowedDomains: z.string(),
  /** Every service in the organization, and where it stands. */
  services: z.array(serviceReport),
});

export type InstallValidation = z.infer<typeof installValidation>;
