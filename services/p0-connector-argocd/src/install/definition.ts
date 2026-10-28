// copy of services/p0-connector-harbor/src/install/definition.ts, with Argo
// CD's facts
import { z } from "zod";

/**
 * The checks install validation runs, in the order it runs them, by the name
 * a failure reports in `payload.step`. P0 reads these, so the set is closed
 * and the order is fixed: a change to either is a change to the contract.
 */
export const ARGOCD_INSTALL_STEPS = [
  "pattern",
  "secret",
  "reachable",
  "version",
  "account",
  "managing_app",
  "rbac_config_map",
  "scopes",
  "p0_policy",
  "policy_loaded",
  "projects",
  "self_check",
  "patch",
] as const;

/** One of {@link ARGOCD_INSTALL_STEPS}, for P0 to parse a payload with. */
export const argoCdInstallStep = z.enum(ARGOCD_INSTALL_STEPS);

/** A check install validation runs, by its `payload.step` name. */
export type ArgoCdInstallStep = z.infer<typeof argoCdInstallStep>;

/**
 * What install validation returns for an instance once every check has
 * passed. A failed check is thrown, so these are facts about an install that
 * works, not results to inspect.
 */
export const installValidation = z.object({
  /** Argo CD's version as the instance reports it, such as `v3.5.5+2f9b0d1`. */
  argoCdVersion: z.string().min(1),
  /** The connector's `ALLOWED_EMAIL_DOMAIN_PATTERN` as it is set, which P0 never stores or sends. */
  allowedEmailDomainPattern: z.string().min(1),
});

/** What install validation answers, as {@link installValidation} infers it. */
export type InstallValidation = z.infer<typeof installValidation>;
