import { createLogger } from "@p0security/connector-core";
import knex, { type Knex } from "knex";

import { type Cloud, type Endpoint, getConfig } from "./clouds/index.ts";

const logger = createLogger();

export type SslConfig = Knex.PgConnectionConfig["ssl"];
export type PoolConfig = Knex.Config["pool"];

export const newClient = async (endpoint: Endpoint, cloud: Cloud) => {
  const config = getConfig(cloud);

  logger.debug(
    { cloud, host: endpoint.host, port: endpoint.port, user: endpoint.user },
    "creating Postgres client"
  );

  return knex({
    client: "pg",
    connection: {
      ...endpoint,
      password: await config.fetchDbPassword(endpoint),
      ssl: await config.sslConfig(),
    },
    pool: await config.poolConfig(),
    log: logger,
    compileSqlOnError: false,
  });
};
