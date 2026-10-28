import { throwAssertNever } from "@p0security/connector";

import type { PoolConfig, SslConfig } from "../dbclient.ts";
import { awsRdsConfig } from "./aws-rds.ts";
import { gcpCloudSqlConfig } from "./gcp-cloudsql.ts";
import { localConfig } from "./localdev.ts";

export type Endpoint = {
  user: string;
  host: string;
  port: number;
};

export type CloudConfig = {
  fetchDbPassword: (endpoint: Endpoint) => Promise<string>;
  poolConfig: () => Promise<PoolConfig>;
  sslConfig: () => Promise<SslConfig>;
};

// TODO share this with pg
export type Cloud = "cloudsql" | "localhost" | "rds";

export const getConfig = (cloud: Cloud): CloudConfig => {
  switch (cloud) {
    case "rds": {
      return awsRdsConfig;
    }
    case "cloudsql": {
      return gcpCloudSqlConfig;
    }
    case "localhost": {
      return localConfig;
    }
    default: {
      throw throwAssertNever(cloud);
    }
  }
};
