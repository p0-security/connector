import { z } from "zod";

/**
 * One target: a PostgreSQL instance or cluster P0 manages, and the database
 * the manager connects to.
 *
 * The manager's secret is absent: the connector is to look it up by `host`
 * in its own environment, in a mapping Terraform sets, so the P0 control
 * plane cannot point the connector at another secret or host.
 */
export const target = z.object({
  host: z.string().min(1),
  // copy of `port` in services/p0-connector-pg/src/accesses/common/definition.ts
  // 65535 is the highest TCP port (input validation only)
  port: z.coerce.number().int().min(1).max(65535),
  database: z.string().min(1),
});

export type Target = z.infer<typeof target>;

export const installContext = z.object({ target });

export type InstallContext = z.infer<typeof installContext>;
