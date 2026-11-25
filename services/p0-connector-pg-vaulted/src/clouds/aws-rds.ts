import awsCaBundle from "aws-ssl-profiles";
import z from "zod";

import type { PoolConfig, SslConfig } from "../dbclient.ts";
import { readManagerCredential } from "../manager.ts";
import type { CloudConfig } from "./index.ts";

const fetchCredential: CloudConfig["fetchCredential"] = (
  { managerSecret },
  dependencies
) => readManagerCredential(managerSecret, dependencies);

const sslConfig = async (): Promise<SslConfig> => {
  return {
    rejectUnauthorized: true,
    ca: awsCaBundle.ca,
  };
};

const poolEnvSchema = z.object({
  DB_POOL_MIN: z.coerce.number().optional().default(1),
  DB_POOL_MAX: z.coerce.number().optional(),
  // Unless there are many databases on the same VPC there is no reason to terminate the connections quickly,
  // so we go for 10 minutes. Gives much quicker responses when db connections can be reused.
  DB_POOL_IDLE_TIMEOUT: z.coerce
    .number()
    .optional()
    .default(10 * 60 * 1000),
  // We've observed particularly on (VPC) cold starts that these times can be
  // a quite a bit longer than originally anticipated, so we sacrifice some time to error
  // to avoid the frequent false negatives we were getting.
  DB_CONNECTION_TIMEOUT: z.coerce
    .number()
    .optional()
    .default(10 * 1000),
});

const poolConfig = async (): Promise<PoolConfig> => {
  const { data, error } = poolEnvSchema.safeParse(process.env);
  if (error) {
    throw new Error("Invalid aws.poolConfig env vars", { cause: error });
  }

  return {
    min: data.DB_POOL_MIN,
    max: data.DB_POOL_MAX,
    idleTimeoutMillis: data.DB_POOL_IDLE_TIMEOUT,
    acquireTimeoutMillis: data.DB_CONNECTION_TIMEOUT,
  };
};

export const awsRdsConfig: CloudConfig = {
  fetchCredential,
  poolConfig,
  sslConfig,
};
