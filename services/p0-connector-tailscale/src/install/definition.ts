import { z } from "zod";

import { tailnetCredentials } from "../credentials.ts";

/**
 * What `install.validation.get` takes: the tailnet, and whether to skip the
 * `posture` check, the one check that writes (it sets and removes
 * `custom:p0_install_check` on a device). The app skips it once the tailnet
 * is installed, so the periodic install check writes nothing to a
 * customer's device. Off by default.
 */
export const installValidationInput = tailnetCredentials.extend({
  skipPostureWrite: z.boolean().optional(),
});

export type InstallValidationInput = z.infer<typeof installValidationInput>;

/** What the `discovery` check counts, for the install to show. */
export const discovery = z.object({
  /** Postures named `posture:p0_*`. */
  p0Postures: z.number(),
});

export type Discovery = z.infer<typeof discovery>;

/**
 * What install validation returns for a tailnet once every check has
 * passed. A failed check is thrown with its name in `payload.step`, so these
 * are facts about an install that works, not results to inspect.
 */
export const installValidation = z.object({
  /** The tailnet the checks ran against. */
  tailnet: z.string(),
  /**
   * The device the `posture` check set and removed its attribute on.
   * Absent when the check was skipped.
   */
  postureCheckDevice: z.string().optional(),
  /**
   * The tailnet's DNS name, such as `tail1234.ts.net`, for people to tell
   * the tailnet by: the domain of its first own device's MagicDNS name.
   * Tailscale's API gives a tailnet's DNS name nowhere else a tailnet's
   * credential can read. Absent when the tailnet has no device of its own.
   */
  dnsName: z.string().optional(),
  discovery,
});

export type InstallValidation = z.infer<typeof installValidation>;
