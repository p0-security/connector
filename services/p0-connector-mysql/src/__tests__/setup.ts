import type { ResourceHierarchySchemaOf } from "@p0security/connector-core";
import knex from "knex";

import type { spec } from "../accesses/role/definition.ts";
import { router } from "../accesses/role/handler.ts";
import { t } from "../router.ts";

export const MYSQL_USER = "root";
export const MYSQL_PASS = "example";
export const MYSQL_HOST = "localhost";
export const MYSQL_PORT = 3306;

export const newDbClient = () =>
  knex({
    client: "mysql2",
    connection: {
      host: MYSQL_HOST,
      user: MYSQL_USER,
      password: MYSQL_PASS,
      database: "sys",
    },
  });

export const newConnClient = () => router(t).createCaller({});

export const newLifecycle = async <
  T extends (client: ReturnType<typeof newDbClient>) => Promise<any>,
>(args: {
  context: {
    requestId: string;
    db: {
      host: string;
      port: number;
      p0User: string;
      cloud: "localhost" | "rds";
    };
  };
  userId: string;
  password: string;
  resourceId: string;
  policies: ResourceHierarchySchemaOf<typeof spec>["Policy"][];
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

      await newDbClient().raw("ALTER USER ?? IDENTIFIED BY ?", [
        userId,
        password,
      ]);

      const testClient = knex({
        client: "mysql2",
        connection: {
          host: MYSQL_HOST,
          user: userId,
          password,
          database: "",
        },
      });
      await testClient.raw("set role ??", [resourceId]);
      await testClient.raw("USE sys;");

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
    }
  };
};
