import { ConnectorError } from "@p0security/connector-core";

/**
 * The steps of the cutoff (`setPoliciesForUser` with no policies) and of the
 * cleanup (`deleteUser`), by the name a failure reports in `payload.step`.
 * The set is closed, because P0 and the customer's operators read it. The
 * README says what each one does.
 */
export const REVOKE_STEPS = [
  "read_login",
  "revoke_roles",
  "retire_login",
  "end_sessions",
  "read_ownership",
  "delete_secret",
  "take_privileges",
  "list_databases",
  "release_owned",
  "drop_login",
] as const;

export type RevokeStep = (typeof REVOKE_STEPS)[number];

/**
 * Runs `run` as `step`: its failure is thrown as a `ConnectorError` with the
 * same type, message and payload, and the step added, and `database` for a
 * step that works in one database. A failure that already names a step keeps
 * it, and so does a failure that is not a `ConnectorError`. Neither value is
 * sensitive.
 */
export const at = async <T>(
  step: RevokeStep,
  run: () => Promise<T>,
  database?: string
): Promise<T> => {
  try {
    return await run();
  } catch (error) {
    if (!(error instanceof ConnectorError) || "step" in error.data.payload) {
      throw error;
    }
    throw new ConnectorError({
      ...error.data,
      payload: {
        ...error.data.payload,
        step,
        ...(database === undefined ? {} : { database }),
      },
    });
  }
};
