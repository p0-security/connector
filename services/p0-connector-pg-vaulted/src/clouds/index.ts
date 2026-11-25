import { throwAssertNever } from "@p0security/connector-core";

import type { PoolConfig, SslConfig } from "../dbclient.ts";
import type {
  ManagerCredential,
  ManagerSecretDependencies,
} from "../manager.ts";
import { awsRdsConfig } from "./aws-rds.ts";
import { localConfig } from "./localdev.ts";

export type Endpoint = {
  managerSecret: string;
  host: string;
  port: number;
  database: string;
};

export type CloudConfig = {
  /** The username and password the connector signs in to `endpoint` with. */
  fetchCredential: (
    endpoint: Endpoint,
    dependencies: ManagerSecretDependencies
  ) => Promise<ManagerCredential>;
  poolConfig: () => Promise<PoolConfig>;
  sslConfig: () => Promise<SslConfig>;
};

export type Cloud = "localhost" | "rds";

export const getConfig = (cloud: Cloud): CloudConfig => {
  switch (cloud) {
    case "rds": {
      return awsRdsConfig;
    }
    case "localhost": {
      return localConfig;
    }
    default: {
      throw throwAssertNever(cloud);
    }
  }
};
