import { createLogger } from "@p0security/connector-core";
import knex, { type Knex } from "knex";

import { type Cloud, type Endpoint, getConfig } from "./clouds/index.ts";
import type { ManagerSecretDependencies } from "./manager.ts";

const logger = createLogger();

export type SslConfig = Knex.PgConnectionConfig["ssl"];
export type PoolConfig = Knex.Config["pool"];

/** What stands in for Secrets Manager and PostgreSQL in tests. */
export type ClientDependencies = ManagerSecretDependencies & {
  /** Builds the client from its config. */
  knex?: (config: Knex.Config) => Knex;
};

/**
 * A client signed in to `endpoint` with the credential `cloud`'s config
 * fetches. It connects on its first statement.
 */
export const newClient = async (
  endpoint: Endpoint,
  cloud: Cloud,
  dependencies: ClientDependencies = {}
) => {
  const { knex: build = knex, ...secretDependencies } = dependencies;
  const { host, port, database } = endpoint;
  const config = getConfig(cloud);

  logger.debug({ cloud, host, port }, "creating Postgres client");

  const { username, password } = await config.fetchCredential(
    endpoint,
    secretDependencies
  );
  return build({
    client: "pg",
    connection: {
      host,
      port,
      database,
      user: username,
      password,
      ssl: await config.sslConfig(),
    },
    pool: await config.poolConfig(),
    log: logger,
    compileSqlOnError: false,
  });
};
