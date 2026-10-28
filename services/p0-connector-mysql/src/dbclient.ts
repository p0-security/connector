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
  // user, not the `p0_iam_manager` user the lifecycle passes. For MySQL the
  // username is only the local-part of the service account email (e.g.
  // `sa@proj.iam.gserviceaccount.com` -> `sa`).
  // https://docs.cloud.google.com/sql/docs/mysql/add-manage-iam-users#grant-db-privileges
  const user =
    cloud === "cloudsql"
      ? (await getServiceAccountEmail()).split("@")[0]
      : endpoint.user;

  logger.debug(
    { cloud, host: endpoint.host, port: endpoint.port, user },
    "creating MySQL client"
  );

  return knex({
    client: "mysql2",
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
