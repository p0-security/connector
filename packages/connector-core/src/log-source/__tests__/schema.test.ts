import { describe, expect, it } from "vitest";

import {
  GapSchema,
  type LogCheckInput,
  LogCheckInputSchema,
  type LogEntry,
  LogEntrySchema,
  type LogQuery,
  LogQuerySchema,
  type LogReadInput,
  LogReadInputSchema,
  type LogReadResult,
  LogReadResultSchema,
} from "../schema.ts";

const window = {
  start: "2026-11-01T10:00:00Z",
  end: "2026-11-01T12:00:00.000+00:00",
};

const queries: Record<string, LogQuery> = {
  "cloudtrail assumed-role pattern": {
    source: "cloudtrail",
    window,
    accountId: "123456789012",
    identity: {
      kind: "assumed-role",
      roleNamePattern: "AWSReservedSSO_P0Grant_abc_*",
      sessionName: "alice@example.com",
    },
    actions: ["s3:GetObject", "s3:List*"],
    resources: ["arn:aws:s3:::bucket/*"],
  },
  "cloudtrail source-identity": {
    source: "cloudtrail",
    window,
    accountId: "123456789012",
    identity: {
      kind: "source-identity",
      value: "alice@example.com",
      roleName: "P0PooledRole",
    },
  },
  "cloudtrail iam-user": {
    source: "cloudtrail",
    window,
    accountId: "123456789012",
    identity: {
      kind: "iam-user",
      userArn: "arn:aws:iam::123456789012:user/alice",
    },
  },
  "gcp-audit": {
    source: "gcp-audit",
    window,
    projectId: "my-project",
    principalEmail: "alice@example.com",
    permissions: ["storage.objects.get"],
    resourcePrefixes: ["//storage.googleapis.com/projects/_/buckets/b"],
  },
  rds: {
    source: "rds",
    window,
    accountId: "123456789012",
    region: "us-west-2",
    instanceId: "db-1",
    engine: "postgres",
    dbUser: "p0_alice",
    database: "app",
    tables: ["public.users"],
  },
  cloudsql: {
    source: "cloudsql",
    window,
    projectId: "my-project",
    instanceId: "db-1",
    engine: "postgres",
    iamEmail: "alice@example.com",
  },
};

describe("LogQuerySchema", () => {
  it.each(Object.entries(queries))("round-trips %s", (_name, query) => {
    expect(LogQuerySchema.parse(query)).toEqual(query);
    expect(LogQuerySchema.parse(JSON.parse(JSON.stringify(query)))).toEqual(
      query
    );
  });

  it("rejects an unknown source", () => {
    expect(
      LogQuerySchema.safeParse({ ...queries["gcp-audit"], source: "azure" })
        .success
    ).toBe(false);
  });

  it("rejects extra keys at the top level and in nested objects", () => {
    const query = queries["cloudtrail iam-user"] as Extract<
      LogQuery,
      { source: "cloudtrail" }
    >;
    expect(
      LogQuerySchema.safeParse({ ...query, filter: "fields @message" }).success
    ).toBe(false);
    expect(
      LogQuerySchema.safeParse({
        ...query,
        identity: { ...query.identity, extra: true },
      }).success
    ).toBe(false);
    expect(
      LogQuerySchema.safeParse({
        ...query,
        window: { ...window, tz: "UTC" },
      }).success
    ).toBe(false);
  });

  it("requires exactly one of roleName and roleNamePattern", () => {
    const base = queries["cloudtrail iam-user"]!;
    const withIdentity = (identity: object) =>
      LogQuerySchema.safeParse({ ...base, identity }).success;
    expect(withIdentity({ kind: "assumed-role", roleName: "R" })).toBe(true);
    expect(withIdentity({ kind: "assumed-role" })).toBe(false);
    expect(
      withIdentity({
        kind: "assumed-role",
        roleName: "R",
        roleNamePattern: "R*",
      })
    ).toBe(false);
  });

  it("requires exactly one of instanceId and clusterId for rds", () => {
    const { instanceId: _, ...rds } = queries.rds as Extract<
      LogQuery,
      { source: "rds" }
    >;
    expect(LogQuerySchema.safeParse(rds).success).toBe(false);
    expect(LogQuerySchema.safeParse({ ...rds, clusterId: "c" }).success).toBe(
      true
    );
    expect(
      LogQuerySchema.safeParse({ ...rds, clusterId: "c", instanceId: "i" })
        .success
    ).toBe(false);
  });

  it("requires a user for cloudsql", () => {
    const { iamEmail: _, ...cloudsql } = queries.cloudsql as Extract<
      LogQuery,
      { source: "cloudsql" }
    >;
    expect(LogQuerySchema.safeParse(cloudsql).success).toBe(false);
  });

  it("rejects a malformed account ID, timestamp or reversed window", () => {
    const base = queries["cloudtrail iam-user"]!;
    expect(
      LogQuerySchema.safeParse({ ...base, accountId: "1234" }).success
    ).toBe(false);
    expect(
      LogQuerySchema.safeParse({
        ...base,
        window: { start: "yesterday", end: window.end },
      }).success
    ).toBe(false);
    expect(
      LogQuerySchema.safeParse({
        ...base,
        window: { start: window.end, end: window.start },
      }).success
    ).toBe(false);
  });
});

const entry: LogEntry = {
  id: "c2f4b5a4-1f0e-4e0a-9c1e-7d6f0c3b2a10",
  time: "2026-11-01T10:15:00Z",
  action: "s3:GetObject",
  resource: "arn:aws:s3:::bucket/key",
  result: "allowed",
  principal:
    "arn:aws:sts::123456789012:assumed-role/AWSReservedSSO_P0Grant_abc_123/alice@example.com",
  raw: { eventID: "c2f4b5a4-1f0e-4e0a-9c1e-7d6f0c3b2a10", nested: { a: [1] } },
};

describe("LogReadResultSchema", () => {
  const result: LogReadResult = {
    entries: [entry],
    cursor: "opaque",
    state: "more",
    checkedThrough: "2026-11-01T11:59:00Z",
    gaps: [
      {
        kind: "not-delivered",
        log: "cloudtrail-data-events",
        service: "s3.amazonaws.com",
        docsAnchor: "turn-on-data-events",
        message: "S3 data events aren't delivered to this trail.",
      },
      {
        kind: "retention",
        retainedFrom: "2026-10-01T00:00:00Z",
        message: "Older entries have expired.",
      },
      { kind: "lag", message: "May still be arriving." },
      {
        kind: "truncated",
        start: window.start,
        end: window.end,
        message: "Too many entries.",
      },
    ],
  };

  it("round-trips through JSON", () => {
    expect(
      LogReadResultSchema.parse(JSON.parse(JSON.stringify(result)))
    ).toEqual(result);
  });

  it("requires a cursor unless done, and none when done", () => {
    expect(
      LogReadResultSchema.safeParse({ ...result, cursor: undefined }).success
    ).toBe(false);
    expect(
      LogReadResultSchema.safeParse({ ...result, state: "done" }).success
    ).toBe(false);
    expect(
      LogReadResultSchema.safeParse({
        entries: [],
        state: "done",
        gaps: [],
      }).success
    ).toBe(true);
  });

  it("rejects extra keys on an entry and an unknown gap kind", () => {
    expect(LogEntrySchema.safeParse({ ...entry, grantId: "g" }).success).toBe(
      false
    );
    expect(
      GapSchema.safeParse({ kind: "no-source", message: "m" }).success
    ).toBe(false);
  });
});

describe("read and check inputs", () => {
  it("round-trip", () => {
    const read: LogReadInput = {
      query: queries["gcp-audit"]!,
      cursor: "c",
      logGroupName: "aws-cloudtrail-logs",
    };
    const check: LogCheckInput = { target: queries.rds! };
    expect(LogReadInputSchema.parse(read)).toEqual(read);
    expect(LogCheckInputSchema.parse(check)).toEqual(check);
  });

  it("reject extra keys", () => {
    expect(
      LogReadInputSchema.safeParse({
        query: queries["gcp-audit"],
        queryText: "x",
      }).success
    ).toBe(false);
  });
});
