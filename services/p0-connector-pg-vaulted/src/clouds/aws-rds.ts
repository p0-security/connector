import {
  type SecretRef,
  createSecretManagerClient,
} from "@p0security/connector-secret-manager-client";
import awsCaBundle from "aws-ssl-profiles";
import z from "zod";

import type { PoolConfig, SslConfig } from "../dbclient.ts";
import type { CloudConfig, Endpoint } from "./index.ts";

const managerCredential = z.object({
  username: z.string().min(1),
  password: z.string().min(1),
});

/**
 * Reads the manager's username and password from `managerSecret`, in the
 * connector's own region. Errors leave out the value and the SDK's cause,
 * since either could hold the password.
 */
export const readManagerCredential = async (managerSecret: string) => {
  const secrets = await createSecretManagerClient({
    provider: "aws",
    region: process.env.AWS_REGION ?? "",
  });
  const { value } = await secrets
    .getSecretValue({ ref: managerSecret as SecretRef })
    .catch(() => {
      throw new Error("pg-vaulted could not read the manager secret");
    });
  const text = typeof value === "string" ? value : value.toString("utf8");
  let json: unknown;
  try {
    json = JSON.parse(text);
  } catch {
    json = undefined;
  }
  const credential = managerCredential.safeParse(json);
  if (!credential.success) {
    throw new Error(
      "pg-vaulted's manager secret must be a JSON object with a username and a password"
    );
  }
  return credential.data;
};

const fetchDbPassword = async (endpoint: Pick<Endpoint, "managerSecret">) =>
  (await readManagerCredential(endpoint.managerSecret)).password;

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
  fetchDbPassword,
  poolConfig,
  sslConfig,
};
