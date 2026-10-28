import { fetchDbPassword } from "@p0security/gcloud-common";
import type { Client } from "pg";
import z from "zod";

import type { PoolConfig, SslConfig } from "../dbclient.ts";
import type { CloudConfig } from "./index.ts";

const SECONDS = 1000;
const MINUTES = 60 * SECONDS;

/* TODO: Verify the per-instance server CA (via a Cloud SQL
 * Admin API call, keyed by instance connection name) instead of `rejectUnauthorized: false`.
 * Cloud SQL has no static CA bundle like RDS's `aws-ssl-profiles`.
 */
const sslConfig = async (): Promise<SslConfig> => {
  return {
    rejectUnauthorized: false,
  };
};

const poolEnvSchema = z.object({
  DB_POOL_MIN: z.coerce.number().optional().default(1),
  DB_POOL_MAX: z.coerce.number().optional(),
  // Unless there are many databases on the same VPC there is no reason to terminate the connections quickly
  // so we go for 10 minutes for now. The Cloud SQL IAM access token used as the password is valid for
  // ~1 hour, so a reused connection is well within the token lifetime. Gives much quicker responses
  // when db connections can be reused.
  DB_POOL_IDLE_TIMEOUT: z.coerce
    .number()
    .optional()
    .default(10 * MINUTES),
  // Pool acquire timeout, which includes creating a new connection. On a scaled-from-zero
  // Cloud Run instance using Direct VPC egress, GCP documents connection delays of "a minute
  // or more" while the VPC interface warms up (same for PSC endpoints or PSA). Default 90s to
  // cover that, trading slower failure on a dead DB for surviving cold starts. Not yet
  // empirically verified on Cloud Run.
  // https://docs.cloud.google.com/run/docs/configuring/vpc-direct-vpc
  DB_CONNECTION_TIMEOUT: z.coerce
    .number()
    .optional()
    .default(90 * SECONDS),
});

const poolConfig = async (): Promise<PoolConfig> => {
  const { data, error } = poolEnvSchema.safeParse(process.env);
  if (error) {
    throw new Error("Invalid gcp-cloudsql.poolConfig env vars", {
      cause: error,
    });
  }

  return {
    min: data.DB_POOL_MIN,
    max: data.DB_POOL_MAX,
    idleTimeoutMillis: data.DB_POOL_IDLE_TIMEOUT,
    acquireTimeoutMillis: data.DB_CONNECTION_TIMEOUT,
    afterCreate: (
      conn: Client,
      done: (err: Error | null, conn: Client) => void
    ) => {
      conn.query("SET ROLE cloudsqlsuperuser", (err) => {
        if (err) {
          conn.end(() => done(err, conn)); // close the TCP socket, then signal pool failure
        } else {
          done(null, conn); // signal pool success; knex takes ownership
        }
      });
    },
  };
};

export const gcpCloudSqlConfig: CloudConfig = {
  fetchDbPassword,
  poolConfig,
  sslConfig,
};
