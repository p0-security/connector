import type {
  CloudSqlLogQuery,
  LogReadResult,
} from "@p0security/connector-core";

import { composeCloudSqlFilter, toCloudSqlEntries } from "../audit/cloudsql.ts";
import type { Logging } from "../logging.ts";
import { queryHash } from "./cursor.ts";
import { readPages } from "./paged-read.ts";

/** Reads a Cloud SQL instance's database audit entries from the project's Data Access log. */
export const readCloudSql = (
  logging: Logging,
  query: CloudSqlLogQuery,
  cursor: string | undefined
): Promise<LogReadResult> =>
  readPages(
    logging,
    {
      projectId: query.projectId,
      window: query.window,
      hash: queryHash(query),
      forEnd: (end) => {
        const paged = { ...query, window: { ...query.window, end } };
        return {
          filter: composeCloudSqlFilter(paged),
          toEntries: toCloudSqlEntries(paged),
        };
      },
      label: "Cloud SQL",
    },
    cursor
  );
