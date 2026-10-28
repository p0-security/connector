import {
  type ResourceHierarchySchemaOf,
  createLogger,
} from "@p0security/connector";
import knex from "knex";
import { escapeLiteral } from "pg";

import type { spec as roleSpec } from "../accesses/role/definition.ts";
import { router as roleRouter } from "../accesses/role/handler.ts";
import type { spec as sqlSpec } from "../accesses/sql/definition.ts";
import { router as sqlRouter } from "../accesses/sql/handler.ts";
import type { Cloud } from "../clouds/index.ts";
import { t } from "../router.ts";

export const PG_USER = "pspladmin";
export const PG_PASS = "psqlpass";
export const PG_HOST = "localhost";
// Overridable for a machine that already runs Postgres on the default port.
export const PG_PORT = Number(process.env.PG_PORT ?? 5432);
export const PG_DATABASE = "postgres";

export const newPgClient = () =>
  knex({
    client: "pg",
    connection: {
      user: PG_USER,
      password: PG_PASS,
      host: PG_HOST,
      port: PG_PORT,
      database: PG_DATABASE,
    },
  });
const rootClient = newPgClient();

const connectorContext = { logger: createLogger() };

export const newConnClient = () => roleRouter(t).createCaller(connectorContext);
export const newSqlConnClient = () =>
  sqlRouter(t).createCaller(connectorContext);

export const dropRole = async (role: string) => {
  await rootClient.raw(`DROP OWNED BY ??`, [role]).catch(() => {});
  await rootClient.raw(`DROP ROLE IF EXISTS ??`, [role]).catch(() => {});
};

/**
 * `ALTER USER ... PASSWORD` takes a string literal, and utility statements
 * accept no bind parameters, so the password has to be escaped inline. `??`
 * still quotes the role name as an identifier.
 */
const setPassword = async (userId: string, password: string) =>
  await rootClient.raw(
    `ALTER USER ?? WITH PASSWORD ${escapeLiteral(password)}`,
    [userId]
  );

export const newRoleLifecycle = async <
  T extends (client: ReturnType<typeof newPgClient>) => Promise<any>,
>(args: {
  context: {
    requestId: string;
    db: {
      host: string;
      port: number;
      database: string;
      p0User: string;
      cloud: Cloud;
    };
  };
  userId: string;
  password: string;
  resourceId: string;
  policies: ResourceHierarchySchemaOf<typeof roleSpec>["Policy"][];
}) => {
  const { context, userId, password, resourceId, policies } = args;

  return async (f: T): Promise<ReturnType<Awaited<T>>> => {
    try {
      await newConnClient().provisionUser({
        userBody: userId,
        context,
      });
      await newConnClient().createAccessResource({
        resourceBody: resourceId,
        context,
      });
      await newConnClient().addPoliciesToResource({
        resourceId,
        policies,
        context,
      });
      await newConnClient().bindAccessResource({
        userId,
        userBody: userId,
        resourceId,
        context,
      });

      await setPassword(userId, password);

      const testClient = newPgClient();

      return await f(testClient);
    } finally {
      await newConnClient().unbindAccessResource({
        userId,
        userBody: userId,
        resourceId,
        context,
      });
      await newConnClient().removePoliciesFromResource({
        resourceId,
        policies,
        context,
      });
      await newConnClient().deleteAccessResource({ resourceId, context });
      await dropRole(userId);
    }
  };
};

export const newSqlLifecycle = async <
  T extends (client: ReturnType<typeof newPgClient>) => Promise<any>,
>(args: {
  context: {
    requestId: string;
    db: {
      host: string;
      port: number;
      database: string;
      p0User: string;
      cloud: Cloud;
    };
  };
  userId: string;
  password: string;
  resourceId: string;
  policies: ResourceHierarchySchemaOf<typeof sqlSpec>["Policy"][];
}) => {
  const { context, userId, password, resourceId, policies } = args;

  return async (f: T): Promise<ReturnType<Awaited<T>>> => {
    try {
      await newSqlConnClient().provisionUser({
        userBody: userId,
        context,
      });
      await newSqlConnClient().createAccessResource({
        resourceBody: resourceId,
        context,
      });
      await newSqlConnClient().addPoliciesToResource({
        resourceId,
        policies,
        context,
      });
      await newSqlConnClient().bindAccessResource({
        userId,
        userBody: userId,
        resourceId,
        context,
      });

      await setPassword(userId, password);

      const testClient = newPgClient();

      return await f(testClient);
    } finally {
      await newSqlConnClient().unbindAccessResource({
        userId,
        userBody: userId,
        resourceId,
        context,
      });
      await newSqlConnClient().removePoliciesFromResource({
        resourceId,
        policies,
        context,
      });
      await newSqlConnClient().deleteAccessResource({ resourceId, context });
      await dropRole(userId);
    }
  };
};
