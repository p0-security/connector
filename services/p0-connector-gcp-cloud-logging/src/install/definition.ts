import { z } from "zod";

/**
 * The checks install validation runs, by the name a failure reports in
 * `payload.step`. P0 reads these, so the set is closed.
 *
 * - `read_logs`: the connector can list the project's Cloud Audit Logs,
 *   Data Access included, which needs `roles/logging.privateLogViewer`.
 */
export const GCP_CLOUD_LOGGING_INSTALL_STEPS = ["read_logs"] as const;

export type GcpCloudLoggingInstallStep =
  (typeof GCP_CLOUD_LOGGING_INSTALL_STEPS)[number];

/** The covered project for a project item; the host project for an organization item. */
export const installInput = z.strictObject({ projectId: z.string().min(1) });

export type InstallInput = z.infer<typeof installInput>;

/** What install validation returns once its check has passed. */
export type InstallValidation = {
  projectId: string;
  /** None yet; kept so warnings can be added without changing the shape. */
  warnings: never[];
};
