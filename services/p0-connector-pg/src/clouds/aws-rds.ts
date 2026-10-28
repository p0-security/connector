import { Signer } from "@aws-sdk/rds-signer";
import { createLogger } from "@p0security/connector-core";
import awsCaBundle from "aws-ssl-profiles";
import z from "zod";

import type { PoolConfig, SslConfig } from "../dbclient.ts";
import type { CloudConfig } from "./index.ts";

const logger = createLogger();

/* https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/UsingWithRDS.IAMDBAuth.html
 * Create a signed token (password) asserting the user is accessing the RDS instance
 * as a given IAM role.
 *
 * The IAM role is loaded from the Lambda execution context, and the token is
 * valid for 15 minutes.
 */
const fetchDbPassword = async (params: {
  host: string;
  port: number;
  user: string;
}): Promise<string> => {
  const signerConfig = {
    hostname: params.host,
    port: params.port,
    username: params.user,
  };
  logger.debug({ signerConfig }, "Creating RDS signer");
  const signer = new Signer(signerConfig);
  try {
    return await signer.getAuthToken();
  } catch (error) {
    logger.error({ error, signerConfig }, "failed to generate RDS auth token");
    throw error;
  }
};

const sslConfig = async (): Promise<SslConfig> => {
  return {
    rejectUnauthorized: true,
    ca: awsCaBundle.ca,
  };
};

const poolEnvSchema = z.object({
  DB_POOL_MIN: z.coerce.number().optional().default(1),
  DB_POOL_MAX: z.coerce.number().optional(),
  // Unless there are many databases on the same VPC there is no reason to terminate the connections quickly
  // so we go for 10 minutes for now which is 2/3s of the time our token is valid for.  Gives much quicker responses
  // when db connections can be reused.
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
  fetchDbPassword,
  poolConfig,
  sslConfig,
};
