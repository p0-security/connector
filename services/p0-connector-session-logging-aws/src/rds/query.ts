import { ConnectorError, type RdsLogQuery } from "@p0security/connector-core";

import { INSIGHTS_ROW_LIMIT } from "../insights.ts";
import { assertQuerySafe, escapeRegex } from "../patterns.ts";

/** An RDS instance or Aurora cluster identifier. */
const IDENTIFIER = /^[a-zA-Z][a-zA-Z0-9-]{0,62}$/;

/**
 * The log group RDS exports the engine's audit log to:
 * `/aws/rds/{instance,cluster}/<id>/{postgresql,audit}`.
 */
export const rdsLogGroupName = (query: RdsLogQuery) => {
  const [kind, id] =
    query.instanceId !== undefined
      ? (["instance", query.instanceId] as const)
      : (["cluster", query.clusterId!] as const);
  if (!IDENTIFIER.test(id)) {
    throw new ConnectorError({
      type: "validation_error",
      message: `${id} isn't an RDS ${kind} identifier`,
      payload: { [kind]: id },
    });
  }
  return `/aws/rds/${kind}/${id}/${query.engine === "postgres" ? "postgresql" : "audit"}`;
};

/**
 * The Logs Insights query for an RDS `LogQuery`: pgaudit lines whose
 * `%u@%d` prefix names the user (and database), or MySQL audit records
 * whose `username` field is the user (and `database` field the database).
 * Tables are narrowed in the connector.
 */
export const composeRdsQuery = (query: RdsLogQuery) => {
  const user = escapeRegex(assertQuerySafe(query.dbUser));
  const database =
    query.database === undefined
      ? undefined
      : escapeRegex(assertQuerySafe(query.database));
  const filters =
    query.engine === "postgres"
      ? [
          "@message like /AUDIT: /",
          `@message like /:${user}@${database ?? "[^:\\s]*"}:\\[\\d+\\]:/`,
        ]
      : [
          // timestamp,serverhost,username,…: the user is the third field.
          `@message like /^[^,]*,[^,]*,${user},/`,
          ...(database === undefined
            ? []
            : [
                // Or no database: CONNECT, and statements before one is chosen.
                `@message like /^[^,]*,[^,]*,${user},[^,]*,[^,]*,[^,]*,[^,]*,(?:'?${database}'?)?,/`,
              ]),
        ];
  return [
    "fields @timestamp, @message, @logStream",
    ...filters.map((f) => `| filter ${f}`),
    `| limit ${INSIGHTS_ROW_LIMIT}`,
  ].join("\n");
};
