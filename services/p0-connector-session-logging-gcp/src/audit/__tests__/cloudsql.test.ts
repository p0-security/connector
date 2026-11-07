import {
  type CloudSqlLogQuery,
  ConnectorError,
  createLogger,
  newConnectorTRPC,
} from "@p0security/connector-core";
import { describe, expect, it } from "vitest";

import { fakeLogging } from "../../__tests__/fake-logging.ts";
import { PROJECT } from "../../__tests__/fixtures.ts";
import { newGcpCloudLoggingRouter } from "../../router.ts";
import { composeCloudSqlFilter, toCloudSqlEntries } from "../cloudsql.ts";
import type { AuditLogEntry } from "../entries.ts";

const DATA_ACCESS = `projects/${PROJECT}/logs/cloudaudit.googleapis.com%2Fdata_access`;

const resource = {
  type: "cloudsql_database",
  labels: {
    project_id: PROJECT,
    database_id: `${PROJECT}:orders-pg`,
    region: "us-central",
  },
};

/** Cloud SQL entries as `entries.list` returns them, modelled on recorded
 * ones with identifiers replaced. */
const pgSelect: AuditLogEntry = {
  protoPayload: {
    "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
    serviceName: "cloudsql.googleapis.com",
    methodName: "cloudsql.instances.query",
    resourceName: `instances/orders-pg`,
    request: {
      "@type": "type.googleapis.com/google.cloud.sql.audit.v1.PgAuditEntry",
      auditClass: "READ",
      auditType: "SESSION",
      chunkCount: "1",
      chunkIndex: "1",
      command: "SELECT",
      database: "orders",
      databaseSessionId: "4521",
      object: "public.orders",
      objectType: "TABLE",
      parameter: "[not logged]",
      statement: "select * from orders where id = 7",
      statementId: "3",
      substatementId: "1",
      user: "alice@example.com",
    },
  },
  insertId: "s=8a1b2c;i=91;b=4f2e;m=12;t=6061;x=01",
  resource,
  timestamp: "2026-11-01T10:15:42.512Z",
  severity: "INFO",
  logName: DATA_ACCESS,
  receiveTimestamp: "2026-11-01T10:15:43.118Z",
};

const pgOtherTable: AuditLogEntry = {
  ...pgSelect,
  protoPayload: {
    ...pgSelect.protoPayload,
    request: {
      ...pgSelect.protoPayload!.request,
      object: "payroll.salaries",
      statement: "select * from payroll.salaries",
    },
  },
  insertId: "pg-other-table",
};

const pgOtherUser: AuditLogEntry = {
  ...pgSelect,
  protoPayload: {
    ...pgSelect.protoPayload,
    request: { ...pgSelect.protoPayload!.request, user: "bob@example.com" },
  },
  insertId: "pg-other-user",
};

const mysqlQuery: AuditLogEntry = {
  protoPayload: {
    "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
    serviceName: "cloudsql.googleapis.com",
    methodName: "cloudsql.instances.query",
    resourceName: "instances/orders-mysql",
    request: {
      "@type": "type.googleapis.com/google.cloud.sql.audit.v1.MysqlAuditEntry",
      cmd: "update",
      connectionId: "2112",
      database: "orders",
      gcpIamAccount: "alice@example.com",
      host: "10.128.0.12",
      ip: "10.128.0.12",
      objects: [{ db: "orders", name: "orders", type: "TABLE" }],
      privUser: "p0_alice",
      query: "UPDATE orders SET status='shipped' WHERE id=7",
      statementId: "11",
      threadId: "2112",
      user: "p0_alice",
    },
  },
  insertId: "mysql-1",
  resource: {
    ...resource,
    labels: { ...resource.labels, database_id: `${PROJECT}:orders-mysql` },
  },
  timestamp: "2026-11-01T10:20:00.000Z",
  logName: DATA_ACCESS,
};

const login: AuditLogEntry = {
  protoPayload: {
    "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
    status: {},
    authenticationInfo: { principalEmail: "alice@example.com" },
    serviceName: "cloudsql.googleapis.com",
    methodName: "cloudsql.instances.login",
    resourceName: "instances/orders-pg",
    authorizationInfo: [
      {
        resource: "instances/orders-pg",
        permission: "cloudsql.instances.login",
        granted: true,
      },
    ],
  },
  insertId: "login-1",
  resource,
  timestamp: "2026-11-01T10:15:00.000Z",
  logName: DATA_ACCESS,
};

const window = { start: "2026-11-01T10:00:00Z", end: "2026-11-01T12:00:00Z" };

const pgQuery: CloudSqlLogQuery = {
  source: "cloudsql",
  window,
  projectId: PROJECT,
  instanceId: "orders-pg",
  engine: "postgres",
  iamEmail: "alice@example.com",
  database: "orders",
  tables: ["public.orders"],
};

const mysqlCloudSqlQuery: CloudSqlLogQuery = {
  source: "cloudsql",
  window,
  projectId: PROJECT,
  instanceId: "orders-mysql",
  engine: "mysql",
  dbUser: "p0_alice",
};

describe("composeCloudSqlFilter", () => {
  it("filters the instance's Data Access entries by user", () => {
    expect(composeCloudSqlFilter(pgQuery)).toBe(
      [
        `logName="${DATA_ACCESS}"`,
        'resource.type="cloudsql_database"',
        `resource.labels.database_id="${PROJECT}:orders-pg"`,
        '(protoPayload.request.user="alice@example.com" OR protoPayload.request.gcpIamAccount="alice@example.com" OR protoPayload.authenticationInfo.principalEmail="alice@example.com")',
        'timestamp>="2026-11-01T10:00:00Z"',
        'timestamp<"2026-11-01T12:00:00Z"',
      ].join("\n")
    );
    expect(composeCloudSqlFilter(mysqlCloudSqlQuery)).toContain(
      '(protoPayload.request.user="p0_alice")'
    );
  });

  it("rejects a malformed instance", () => {
    expect(() =>
      composeCloudSqlFilter({ ...pgQuery, instanceId: 'x" OR "' })
    ).toThrow(ConnectorError);
  });
});

describe("toCloudSqlEntries", () => {
  it("keeps the user's pgAudit records on the granted tables, and IAM logins", () => {
    const entries = toCloudSqlEntries(pgQuery)([
      pgSelect,
      pgOtherTable,
      pgOtherUser,
      login,
    ]);
    expect(entries).toEqual([
      {
        id: pgSelect.insertId,
        time: "2026-11-01T10:15:42.512Z",
        action: "SELECT",
        resource: "public.orders",
        result: "allowed",
        principal: "alice@example.com",
        raw: pgSelect,
      },
      expect.objectContaining({
        id: "login-1",
        action: "cloudsql.instances.login",
        principal: "alice@example.com",
      }),
    ]);
  });

  it("normalizes MySQL audit records", () => {
    expect(toCloudSqlEntries(mysqlCloudSqlQuery)([mysqlQuery, login])).toEqual([
      expect.objectContaining({
        id: "mysql-1",
        action: "UPDATE",
        resource: "orders.orders",
        principal: "p0_alice",
        result: "allowed",
      }),
    ]);
  });

  it("narrows by database and marks refusals denied", () => {
    expect(
      toCloudSqlEntries({ ...mysqlCloudSqlQuery, database: "billing" })([
        mysqlQuery,
      ])
    ).toEqual([]);
    expect(
      toCloudSqlEntries(mysqlCloudSqlQuery)([
        {
          ...mysqlQuery,
          protoPayload: { ...mysqlQuery.protoPayload, status: { code: 7 } },
        },
      ])[0]!.result
    ).toBe("denied");
  });
});

describe("toCloudSqlEntries edge cases", () => {
  it("keeps only IAM logins among the instance's other Data Access entries", () => {
    const apiCall = {
      ...login,
      insertId: "api-1",
      protoPayload: {
        ...login.protoPayload,
        methodName: "cloudsql.instances.get",
      },
    };
    expect(toCloudSqlEntries(pgQuery)([apiCall])).toEqual([]);
  });

  it("marks a login refused on every check as denied", () => {
    const refused = {
      ...login,
      protoPayload: {
        ...login.protoPayload,
        authorizationInfo: [
          {
            resource: "instances/orders-pg",
            permission: "cloudsql.instances.login",
            granted: false,
          },
        ],
      },
    };
    expect(toCloudSqlEntries(pgQuery)([refused])[0]!.result).toBe("denied");
  });

  it("tells Postgres tables apart by case, as pgAudit quotes them", () => {
    const quoted = {
      ...pgSelect,
      protoPayload: {
        ...pgSelect.protoPayload,
        request: {
          ...pgSelect.protoPayload!.request,
          object: 'public."Orders"',
        },
      },
    };
    expect(toCloudSqlEntries(pgQuery)([quoted])).toEqual([]);
    expect(
      toCloudSqlEntries({ ...pgQuery, tables: ["public.Orders"] })([quoted])
    ).toHaveLength(1);
  });
});

describe("logs.read for cloudsql", () => {
  it("reads through entries.list on the instance's project", async () => {
    const logging = fakeLogging(() => ({ entries: [pgSelect, pgOtherUser] }));
    const caller = newConnectorTRPC().createCallerFactory(
      newGcpCloudLoggingRouter(logging.dependencies)
    )({ logger: createLogger() })["gcp-cloud-logging"];
    const result = await caller.logs.read({ query: pgQuery });
    expect(result.entries.map((e) => e.id)).toEqual([pgSelect.insertId]);
    expect(logging.requests[0]!.resourceNames).toEqual([`projects/${PROJECT}`]);
    expect(await caller.logs.check({ target: pgQuery })).toEqual({ gaps: [] });
  });
});
