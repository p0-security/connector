import {
  DescribeDBClustersCommand,
  DescribeDBInstancesCommand,
  RDSClient,
} from "@aws-sdk/client-rds";
import {
  type SecretRef,
  createSecretManagerClient,
} from "@p0security/connector-secret-manager-client";
import awsCaBundle from "aws-ssl-profiles";
import z from "zod";

import { RDS_MANAGER_SECRET_ARN_PATTERN } from "../accesses/common/definition.ts";
import type { PoolConfig, SslConfig } from "../dbclient.ts";
import type { CloudConfig, Endpoint } from "./index.ts";

const managerCredential = z.object({
  username: z.string().min(1),
  password: z.string().min(1),
  // Only a secret P0 names holds it.
  host: z.string().min(1).optional(),
});

/** The secret's region: the one its ARN names, or else the connector's own,
 * where a secret P0 names lives. */
const secretRegion = (managerSecret: string) => {
  const region =
    RDS_MANAGER_SECRET_ARN_PATTERN.exec(managerSecret)?.groups?.region ??
    process.env.AWS_REGION;
  if (!region) {
    throw new Error("pg-vaulted could not tell the manager secret's region");
  }
  return region;
};

/**
 * Whether `host` is an endpoint of the RDS instance or cluster whose master
 * user secret is `managerSecret`. A secret RDS manages holds no host, so RDS
 * is asked, by the identifier that is the host's first label.
 */
const isRdsSecretFor = async (
  managerSecret: string,
  kind: string,
  region: string,
  host: string
) => {
  const rds = new RDSClient({ region });
  const [identifier] = host.split(".");
  const wanted = host.toLowerCase();
  const isWanted = (endpoint?: string) => endpoint?.toLowerCase() === wanted;
  if (kind === "db") {
    const { DBInstances = [] } = await rds.send(
      new DescribeDBInstancesCommand({ DBInstanceIdentifier: identifier })
    );
    return DBInstances.some(
      (instance) =>
        instance.MasterUserSecret?.SecretArn === managerSecret &&
        isWanted(instance.Endpoint?.Address)
    );
  }
  const { DBClusters = [] } = await rds.send(
    new DescribeDBClustersCommand({ DBClusterIdentifier: identifier })
  );
  return DBClusters.some(
    (cluster) =>
      cluster.MasterUserSecret?.SecretArn === managerSecret &&
      (isWanted(cluster.Endpoint) || isWanted(cluster.ReaderEndpoint))
  );
};

/**
 * Reads the manager's username and password from `managerSecret`, in the
 * secret's region, once the secret is for `host`: a request names the secret
 * and the host apart, so it could otherwise send the password to a host it is
 * not for. A secret P0 names holds its host. For a secret RDS manages, RDS is
 * asked before the secret is read. Errors leave out the value and the SDK's
 * cause, since either could hold the password.
 */
export const readManagerCredential = async (
  managerSecret: string,
  host: string
) => {
  const region = secretRegion(managerSecret);
  const rdsSecret = RDS_MANAGER_SECRET_ARN_PATTERN.exec(managerSecret)?.groups;
  if (rdsSecret?.kind) {
    const isFor = await isRdsSecretFor(
      managerSecret,
      rdsSecret.kind,
      region,
      host
    ).catch(() => false);
    if (!isFor) {
      throw new Error(
        "pg-vaulted could not confirm the manager secret is for this host"
      );
    }
  }
  const secrets = await createSecretManagerClient({ provider: "aws", region });
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
  if (
    !rdsSecret &&
    credential.data.host?.toLowerCase() !== host.toLowerCase()
  ) {
    throw new Error("pg-vaulted's manager secret is not for this host");
  }
  const { username, password } = credential.data;
  return { username, password };
};

/** Returns the manager's password, once the secret's username is the
 * request's too. */
const fetchDbPassword = async (
  endpoint: Pick<Endpoint, "host" | "managerSecret" | "user">
) => {
  const { username, password } = await readManagerCredential(
    endpoint.managerSecret,
    endpoint.host
  );
  if (username !== endpoint.user) {
    throw new Error("pg-vaulted's manager secret is not for this username");
  }
  return password;
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
