import { createLogger } from "@p0security/connector";
import { getServiceAccountEmail } from "@p0security/gcloud-common";
import knex, { type Knex } from "knex";

import { type Cloud, type Endpoint, getConfig } from "./clouds/index.ts";

const logger = createLogger();

export type SslConfig = Knex.PgConnectionConfig["ssl"];
export type PoolConfig = Knex.Config["pool"];

export const newClient = async (endpoint: Endpoint, cloud: Cloud) => {
  const config = getConfig(cloud);

  // Cloud SQL IAM auth connects as the connector service account's own database
  // user, not the `p0_iam_manager` user the lifecycle passes. For Postgres the
  // username is the service account email with the `.gserviceaccount.com`
  // suffix removed (e.g. `sa@proj.iam.gserviceaccount.com` -> `sa@proj.iam`).
  // https://docs.cloud.google.com/sql/docs/postgres/add-manage-iam-users#creating-a-database-user
  const user =
    cloud === "cloudsql"
      ? (await getServiceAccountEmail()).replace(/\.gserviceaccount\.com$/, "")
      : endpoint.user;

  logger.debug(
    { cloud, host: endpoint.host, port: endpoint.port, user },
    "creating Postgres client"
  );

  return knex({
    client: "pg",
    connection: {
      ...endpoint,
      user,
      password: await config.fetchDbPassword(endpoint),
      ssl: await config.sslConfig(),
    },
    pool: await config.poolConfig(),
    log: logger,
    compileSqlOnError: false,
  });
};
