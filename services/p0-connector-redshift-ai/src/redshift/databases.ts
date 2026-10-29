import type { Logger } from "@p0security/connector-core";

import { isIdentifier } from "../sql.ts";
import type { RedshiftSession } from "./data-api.ts";

/**
 * The target's local databases, from `SHOW DATABASES`. A database whose name
 * P0 can't quote is skipped, with a warning.
 */
export const localDatabases = async (
  session: RedshiftSession,
  logger: Logger
) => {
  const databases = await session.query<{
    database_name: string;
    database_type: string;
  }>("SHOW DATABASES;");
  return databases
    .filter(({ database_type }) => database_type === "local")
    .map(({ database_name }) => database_name)
    .filter((name) => {
      if (isIdentifier(name)) return true;
      logger.warn({ database: name }, "skipped a database P0 can't quote");
      return false;
    });
};
