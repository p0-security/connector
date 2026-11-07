import {
  ConnectorError,
  type LogQuery,
  type RdsLogQuery,
  createLogger,
  newConnectorTRPC,
} from "@p0security/connector-core";
import { describe, expect, it } from "vitest";

import { fakeAws } from "../../__tests__/fake-aws.ts";
import { ACCOUNT } from "../../__tests__/fixtures.ts";
import { newAwsCloudWatchRouter } from "../../router.ts";
import { toRdsEntries } from "../entries.ts";
import { parseMySqlAuditLine, parsePgAuditLine, splitCsv } from "../parse.ts";
import { composeRdsQuery, rdsLogGroupName } from "../query.ts";

/** pgaudit lines as RDS exports them, with RDS's default prefix and the
 * alternative one with milliseconds, session id and application name. */
const PG = {
  select:
    '2026-11-01 10:15:42 UTC:10.0.1.23(53422):p0_alice@app:[12345]:LOG:  AUDIT: SESSION,3,1,READ,SELECT,TABLE,public.users,"select id, email from users where id = $1",<not logged>',
  update:
    '2026-11-01 10:16:01.513 UTC:10.0.1.23(53422):p0_alice@app:[12345]:7:00000:2026-11-01 10:10:00 UTC:3/1201:0:6724a1b2.3039:psql:LOG:  AUDIT: SESSION,4,1,WRITE,UPDATE,TABLE,public.orders,"update orders set status = \'\'shipped\'\' where id = 7 and note = ""a, b""",<not logged>',
  otherTable:
    '2026-11-01 10:17:00 UTC:10.0.1.23(53422):p0_alice@app:[12345]:LOG:  AUDIT: SESSION,5,1,READ,SELECT,TABLE,payroll.salaries,"select * from payroll.salaries",<not logged>',
  misc: "2026-11-01 10:17:30 UTC:10.0.1.23(53422):p0_alice@app:[12345]:LOG:  AUDIT: SESSION,6,1,MISC,SET,,,set search_path = public,<not logged>",
  otherUser:
    '2026-11-01 10:18:00 UTC:10.0.1.99(41000):p0_bob@app:[12399]:LOG:  AUDIT: SESSION,1,1,READ,SELECT,TABLE,public.users,"select 1 from users",<not logged>',
  ipv6: '2026-11-01 10:18:30 UTC:2001:db8::17(50110):p0_alice@app:[12400]:LOG:  AUDIT: SESSION,1,1,READ,SELECT,TABLE,public.users,"select 2 from users",<not logged>',
  connection:
    "2026-11-01 10:10:00 UTC:10.0.1.23(53422):p0_alice@app:[12345]:LOG:  connection authorized: user=p0_alice database=app SSL enabled",
};

/** MySQL audit records: the RDS MariaDB plugin, and Aurora's epoch-µs form. */
const MYSQL = {
  connect:
    "20261101 10:15:00,ip-10-0-1-5,p0_alice,10.0.1.23,1234,0,CONNECT,app,,0",
  query:
    "20261101 10:15:42,ip-10-0-1-5,p0_alice,10.0.1.23,1234,5678,QUERY,app,'SELECT * FROM orders WHERE note = \\'a, b\\'',0",
  read: "20261101 10:15:42,ip-10-0-1-5,p0_alice,10.0.1.23,1234,5678,READ,app,orders,",
  denied:
    "20261101 10:16:10,ip-10-0-1-5,p0_alice,10.0.1.23,1234,5680,QUERY,app,'DELETE FROM payroll',1142",
  aurora:
    "1730456200123456,ip-10-0-2-9,p0_alice,10.0.1.23,88,901,QUERY,app,'update orders set status=\\'x\\'',0",
  rdsadmin:
    "20261101 10:15:43,ip-10-0-1-5,rdsadmin,localhost,2,3,QUERY,,'SELECT 1',0",
};

const window = { start: "2026-11-01T10:00:00Z", end: "2026-11-01T12:00:00Z" };

const pgQuery: RdsLogQuery = {
  source: "rds",
  window,
  accountId: ACCOUNT,
  region: "us-west-2",
  instanceId: "app-db-1",
  engine: "postgres",
  dbUser: "p0_alice",
  database: "app",
  tables: ["public.users", "public.orders"],
};

const mysqlQuery: RdsLogQuery = {
  ...pgQuery,
  instanceId: undefined,
  clusterId: "app-aurora",
  engine: "mysql",
  tables: undefined,
};

/** An Insights row for a line, logged at `time`. */
const row = (message: string, time = "2026-11-01 10:15:42.000") => ({
  "@timestamp": time,
  "@message": message,
  "@logStream": "app-db-1",
});

describe("splitCsv", () => {
  it("handles quoted fields with doubled and backslash-escaped quotes", () => {
    expect(splitCsv('a,"b ""c"", d",e', '"')).toEqual(["a", 'b "c", d', "e"]);
    expect(splitCsv("a,'b \\'c\\', d',,e", "'")).toEqual([
      "a",
      "b 'c', d",
      "",
      "e",
    ]);
  });
});

describe("parsePgAuditLine", () => {
  it("reads the user and database from the prefix and the audit record", () => {
    expect(parsePgAuditLine(PG.select)).toEqual({
      user: "p0_alice",
      database: "app",
      auditType: "SESSION",
      statementId: "3",
      substatementId: "1",
      class: "READ",
      command: "SELECT",
      objectType: "TABLE",
      objectName: "public.users",
      statement: "select id, email from users where id = $1",
    });
  });

  it("reads the longer prefix, IPv6 clients and quoted statements", () => {
    expect(parsePgAuditLine(PG.update)).toMatchObject({
      user: "p0_alice",
      command: "UPDATE",
      objectName: "public.orders",
      statement:
        "update orders set status = ''shipped'' where id = 7 and note = \"a, b\"",
    });
    expect(parsePgAuditLine(PG.ipv6)).toMatchObject({
      user: "p0_alice",
      database: "app",
    });
  });

  it("keeps backslashes in pgaudit fields", () => {
    expect(splitCsv("READ,\"SELECT 'C:\\temp'\",x", '"')).toEqual([
      "READ",
      "SELECT 'C:\\temp'",
      "x",
    ]);
  });

  it("reads a user and database whose names hold @, for a known user", () => {
    const line = PG.select.replace(
      "p0_alice@app",
      "alice@example.com@app@prod"
    );
    expect(parsePgAuditLine(line, "alice@example.com")).toMatchObject({
      user: "alice@example.com",
      database: "app@prod",
    });
    expect(parsePgAuditLine(line, "p0_alice")).toBeUndefined();
  });

  it("ignores lines that aren't audit records", () => {
    expect(parsePgAuditLine(PG.connection)).toBeUndefined();
    expect(parsePgAuditLine("garbage")).toBeUndefined();
  });
});

describe("parseMySqlAuditLine", () => {
  it("reads RDS and Aurora records", () => {
    expect(parseMySqlAuditLine(MYSQL.query)).toEqual({
      time: Date.parse("2026-11-01T10:15:42Z"),
      serverHost: "ip-10-0-1-5",
      user: "p0_alice",
      host: "10.0.1.23",
      connectionId: "1234",
      queryId: "5678",
      operation: "QUERY",
      database: "app",
      object: "SELECT * FROM orders WHERE note = 'a, b'",
      retcode: 0,
    });
    expect(parseMySqlAuditLine(MYSQL.aurora)).toMatchObject({
      time: 1730456200123,
      object: "update orders set status='x'",
    });
    expect(parseMySqlAuditLine(MYSQL.read)).toMatchObject({
      operation: "READ",
      object: "orders",
      retcode: 0,
    });
  });

  it("ignores anything else", () => {
    expect(parseMySqlAuditLine("hello, world")).toBeUndefined();
  });
});

describe("rdsLogGroupName and composeRdsQuery", () => {
  it("derives the log group from the instance or cluster and engine", () => {
    expect(rdsLogGroupName(pgQuery)).toBe(
      "/aws/rds/instance/app-db-1/postgresql"
    );
    expect(rdsLogGroupName(mysqlQuery)).toBe(
      "/aws/rds/cluster/app-aurora/audit"
    );
    expect(() => rdsLogGroupName({ ...pgQuery, instanceId: "../x" })).toThrow(
      ConnectorError
    );
  });

  it("pushes the user and database down", () => {
    expect(composeRdsQuery(pgQuery)).toBe(
      [
        "fields @timestamp, @message, @logStream",
        "| filter @message like /AUDIT: /",
        "| filter @message like /:p0_alice@app:\\[\\d+\\]:/",
        "| limit 10000",
      ].join("\n")
    );
    expect(composeRdsQuery(mysqlQuery)).toContain(
      "| filter @message like /^[^,]*,[^,]*,p0_alice,/"
    );
    // A Postgres database name may hold @.
    expect(composeRdsQuery({ ...pgQuery, database: undefined })).toContain(
      "| filter @message like /:p0_alice@[^:\\s]*:\\[\\d+\\]:/"
    );
  });

  it("keeps MySQL records with no database when one is asked for", () => {
    const filter = composeRdsQuery(mysqlQuery)
      .split("\n")
      .find((line) => line.includes(",(?:"))!;
    const pattern = new RegExp(/\/(.*)\//.exec(filter)![1]!);
    expect(pattern.test(MYSQL.connect)).toBe(true);
    expect(pattern.test(MYSQL.connect.replace(",app,", ",,"))).toBe(true);
    expect(pattern.test(MYSQL.connect.replace(",app,", ",other,"))).toBe(false);
  });
});

describe("toRdsEntries", () => {
  const bounds = { start: 0, end: Number.MAX_SAFE_INTEGER };

  it("keeps the user's statements on the granted tables", () => {
    const entries = toRdsEntries(pgQuery)(
      [
        row(PG.select),
        row(PG.update),
        row(PG.otherTable),
        row(PG.misc),
        row(PG.otherUser),
        row(PG.connection),
      ],
      bounds
    );
    expect(entries.map((e) => [e.action, e.resource])).toEqual([
      ["SELECT", "public.users"],
      ["UPDATE", "public.orders"],
      ["SET", "app"],
    ]);
    expect(entries[0]).toMatchObject({
      time: "2026-11-01T10:15:42.000Z",
      principal: "p0_alice",
      result: "allowed",
      raw: { message: PG.select, statement: expect.any(String) },
    });
    // IDs are stable and distinct.
    expect(toRdsEntries(pgQuery)([row(PG.select)], bounds)[0]!.id).toBe(
      entries[0]!.id
    );
    expect(new Set(entries.map((e) => e.id)).size).toBe(3);
  });

  it("tells Postgres tables apart by case, as pgaudit quotes them", () => {
    const users = PG.select.replace("public.users", 'public."Users"');
    expect(toRdsEntries(pgQuery)([row(users)], bounds)).toEqual([]);
    expect(
      toRdsEntries({ ...pgQuery, tables: ["public.Users"] })(
        [row(users)],
        bounds
      )
    ).toHaveLength(1);
  });

  it("normalizes MySQL records and marks access denied", () => {
    const entries = toRdsEntries(mysqlQuery)(
      [
        row(MYSQL.connect),
        row(MYSQL.query),
        row(MYSQL.read),
        row(MYSQL.denied),
        row(MYSQL.rdsadmin),
      ],
      bounds
    );
    expect(entries.map((e) => [e.action, e.resource, e.result])).toEqual([
      ["CONNECT", "app", "allowed"],
      ["SELECT", "app", "allowed"],
      ["READ", "app.orders", "allowed"],
      ["DELETE", "app", "denied"],
    ]);
  });

  it("narrows MySQL table events by table", () => {
    const entries = toRdsEntries({ ...mysqlQuery, tables: ["app.customers"] })(
      [row(MYSQL.read), row(MYSQL.query)],
      bounds
    );
    expect(entries.map((e) => e.action)).toEqual(["SELECT"]);
  });
});

describe("logs.read for rds", () => {
  const callerFor = (aws: ReturnType<typeof fakeAws>) =>
    newConnectorTRPC().createCallerFactory(
      newAwsCloudWatchRouter(aws.dependencies)
    )({
      logger: createLogger(),
    })["aws-cloudwatch"];

  it("reads the instance's log group without a logGroupName", async () => {
    const aws = fakeAws(() => [row(PG.select), row(PG.otherUser)]);
    const result = await callerFor(aws).logs.read({ query: pgQuery });
    expect(result.state).toBe("done");
    expect(result.entries).toHaveLength(1);
    expect(aws.queries[0]!.logGroupName).toBe(
      "/aws/rds/instance/app-db-1/postgresql"
    );
  });

  it("reports a missing log group as no database logs", async () => {
    const aws = fakeAws();
    aws.on("DescribeLogGroupsCommand", () => ({ logGroups: [] }));
    const result = await callerFor(aws).logs.read({ query: mysqlQuery });
    expect(result).toEqual({
      entries: [],
      state: "done",
      gaps: [
        expect.objectContaining({
          kind: "not-delivered",
          log: "database-audit",
          message: "No database logs found for this instance.",
        }),
      ],
    });
  });

  it("checks nothing for rds", async () => {
    const aws = fakeAws();
    const target: LogQuery = pgQuery;
    expect(await callerFor(aws).logs.check({ target })).toEqual({ gaps: [] });
    expect(aws.calls).toEqual([]);
  });
});
