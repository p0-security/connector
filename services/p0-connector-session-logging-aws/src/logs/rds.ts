import type { LogReadResult, RdsLogQuery } from "@p0security/connector-core";

import type { Aws } from "../aws.ts";
import { toRdsEntries } from "../rds/entries.ts";
import { composeRdsQuery, rdsLogGroupName } from "../rds/query.ts";
import { queryHash } from "./cursor.ts";
import { readInsights } from "./insights-read.ts";

/**
 * Reads an RDS instance's or Aurora cluster's exported audit log. The log
 * group follows from the query, so no item config is needed; a missing group
 * means auditing or log export is off, and comes back as a gap.
 */
export const readRds = (
  aws: Aws,
  query: RdsLogQuery,
  cursor: string | undefined
): Promise<LogReadResult> => {
  const logGroupName = rdsLogGroupName(query);
  return readInsights(
    aws,
    {
      logGroupName,
      queryString: composeRdsQuery(query),
      window: {
        start: Date.parse(query.window.start),
        end: Date.parse(query.window.end),
      },
      hash: queryHash(query, logGroupName),
      toEntries: toRdsEntries(query),
      missingGroup: {
        kind: "not-delivered",
        log: "database-audit",
        docsAnchor: "turn-on-database-auditing",
        message: "No database logs found for this instance.",
      },
      label: "Database",
    },
    cursor
  );
};
