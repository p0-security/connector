// shape copied from services/p0-connector-redshift-ai/src/install/definition.ts

/**
 * The checks install validation runs, by the name a failure reports in
 * `payload.step`. P0 reads these, so the set is closed.
 *
 * - `managed_instances`: the execution role can describe the SSM managed
 *   instances in the install's region.
 */
export const SSH_AI_INSTALL_STEPS = ["managed_instances"] as const;

export type SshAiInstallStep = (typeof SSH_AI_INSTALL_STEPS)[number];

/**
 * What install validation returns once every check has passed. Validation
 * throws the first check that fails, with its name in `payload.step`.
 */
export type InstallValidation = {
  /** The region the connector read SSM's managed instances in. */
  region: string;
};
