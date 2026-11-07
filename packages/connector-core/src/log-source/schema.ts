import { z } from "zod";

/**
 * The `logs` route contract: what P0 asks a log-source connector for, and
 * what the connector answers with.
 *
 * Every query is a closed union member, never query text. The connector
 * composes the source's own query (Logs Insights, a Cloud Logging filter)
 * from these fields itself, the same way an `sql` access crosses as a closed
 * policy union rather than as SQL. Every object is strict, so a field the
 * connector doesn't know is a validation error rather than silently dropped.
 */

/** An ISO 8601 timestamp with a `Z` or numeric offset. */
const IsoTimestampSchema = z.iso.datetime({ offset: true });

const nonEmpty = z.string().min(1);

/**
 * The time range to read, already extended or skewed by the grant
 * integration. `start` is inclusive, `end` is exclusive.
 */
export const LogWindowSchema = z
  .strictObject({ start: IsoTimestampSchema, end: IsoTimestampSchema })
  .refine((w) => Date.parse(w.start) <= Date.parse(w.end), {
    message: "window.start must not be after window.end",
  });

/** A twelve-digit AWS account ID. */
const AwsAccountIdSchema = z.string().regex(/^\d{12}$/);

/**
 * A role session: `roleName` matches the role exactly, `roleNamePattern`
 * matches it with `*` standing for any run of characters (e.g.
 * `AWSReservedSSO_P0Grant_*`). Exactly one of the two is set.
 */
export const CloudTrailAssumedRoleIdentitySchema = z
  .strictObject({
    kind: z.literal("assumed-role"),
    roleName: nonEmpty.optional(),
    roleNamePattern: nonEmpty.optional(),
    sessionName: nonEmpty.optional(),
  })
  .refine(
    (i) => (i.roleName === undefined) !== (i.roleNamePattern === undefined),
    {
      message: "exactly one of roleName and roleNamePattern must be set",
    }
  );

/** A role session whose `sourceIdentity` is `value` (a pooled federated role). */
export const CloudTrailSourceIdentitySchema = z.strictObject({
  kind: z.literal("source-identity"),
  value: nonEmpty,
  roleName: nonEmpty.optional(),
});

/** An IAM user's own calls. */
export const CloudTrailIamUserIdentitySchema = z.strictObject({
  kind: z.literal("iam-user"),
  userArn: nonEmpty,
});

export const CloudTrailIdentitySchema = z.discriminatedUnion("kind", [
  CloudTrailAssumedRoleIdentitySchema,
  CloudTrailSourceIdentitySchema,
  CloudTrailIamUserIdentitySchema,
]);

/**
 * CloudTrail events in one AWS account.
 *
 * `actions` are IAM action patterns (`s3:GetObject`, `s3:Get*`) and
 * `resources` are ARN patterns (`arn:aws:s3:::bucket/*`), both with IAM's
 * `*` and `?` wildcards, taken from the policy P0 wrote. When set, an event
 * must match at least one pattern of each.
 */
export const CloudTrailLogQuerySchema = z.strictObject({
  source: z.literal("cloudtrail"),
  window: LogWindowSchema,
  accountId: AwsAccountIdSchema,
  identity: CloudTrailIdentitySchema,
  actions: z.array(nonEmpty).optional(),
  resources: z.array(nonEmpty).optional(),
});

/**
 * Cloud Audit Logs in one GCP project.
 *
 * `permissions` are the granted role's permissions
 * (`storage.objects.get`); `resourcePrefixes` are full resource names the
 * grant is scoped to (`projects/p`, `//storage.googleapis.com/projects/_/buckets/b`).
 * When set, an entry must match at least one of each.
 */
export const GcpAuditLogQuerySchema = z.strictObject({
  source: z.literal("gcp-audit"),
  window: LogWindowSchema,
  projectId: nonEmpty,
  principalEmail: nonEmpty,
  permissions: z.array(nonEmpty).optional(),
  resourcePrefixes: z.array(nonEmpty).optional(),
});

/** The database engine family, independent of the hosting (RDS, Aurora, Cloud SQL). */
export const DatabaseEngineSchema = z.enum(["postgres", "mysql"]);

/**
 * Phase 2: database audit logs an RDS instance or Aurora cluster exports to
 * CloudWatch Logs (pgaudit or the MySQL audit plugin). Exactly one of
 * `instanceId` and `clusterId` is set. `tables` are `schema.table` (Postgres)
 * or `database.table` (MySQL) names.
 */
export const RdsLogQuerySchema = z
  .strictObject({
    source: z.literal("rds"),
    window: LogWindowSchema,
    accountId: AwsAccountIdSchema,
    region: nonEmpty,
    instanceId: nonEmpty.optional(),
    clusterId: nonEmpty.optional(),
    engine: DatabaseEngineSchema,
    dbUser: nonEmpty,
    database: nonEmpty.optional(),
    tables: z.array(nonEmpty).optional(),
  })
  .refine((q) => (q.instanceId === undefined) !== (q.clusterId === undefined), {
    message: "exactly one of instanceId and clusterId must be set",
  });

/**
 * Phase 2: Cloud SQL database audit entries (`cloudaudit.googleapis.com/data_access`).
 * `dbUser` matches the database user (`protoPayload.request.user`),
 * `iamEmail` the IAM principal behind an IAM database login
 * (`protoPayload.request.gcpIamAccount`). At least one is set.
 */
export const CloudSqlLogQuerySchema = z
  .strictObject({
    source: z.literal("cloudsql"),
    window: LogWindowSchema,
    projectId: nonEmpty,
    instanceId: nonEmpty,
    engine: DatabaseEngineSchema,
    dbUser: nonEmpty.optional(),
    iamEmail: nonEmpty.optional(),
    database: nonEmpty.optional(),
    tables: z.array(nonEmpty).optional(),
  })
  .refine((q) => q.dbUser !== undefined || q.iamEmail !== undefined, {
    message: "at least one of dbUser and iamEmail must be set",
  });

/** What P0 asks a log-source connector to read, closed on `source`. */
export const LogQuerySchema = z.discriminatedUnion("source", [
  CloudTrailLogQuerySchema,
  GcpAuditLogQuerySchema,
  RdsLogQuerySchema,
  CloudSqlLogQuerySchema,
]);

export const LogSourceSchema = z.enum([
  "cloudtrail",
  "gcp-audit",
  "rds",
  "cloudsql",
]);

/** One entry from the source, already narrowed to the grant. */
export const LogEntrySchema = z.strictObject({
  /** The source's own entry ID: CloudTrail `eventID`, GCP `insertId`. */
  id: nonEmpty,
  time: IsoTimestampSchema,
  /** The source's own name for the action: `s3:GetObject`, `storage.objects.get`, `SELECT`. */
  action: nonEmpty,
  resource: nonEmpty.optional(),
  result: z.enum(["allowed", "denied"]),
  /** Who the source says acted: an ARN, an email, a database user. */
  principal: nonEmpty,
  /** The full source entry, for the detail panel. */
  raw: z.record(z.string(), z.unknown()),
});

/**
 * Which kind of log a `not-delivered` gap is about.
 *
 * - `cloudtrail`: no CloudTrail log group, or the group holds no events.
 * - `cloudtrail-data-events`: the trail doesn't deliver data events for `service`.
 * - `gcp-data-access`: Data Access audit logs are off for `service`.
 * - `database-audit`: no database audit logs for the instance.
 */
export const NotDeliveredLogKindSchema = z.enum([
  "cloudtrail",
  "cloudtrail-data-events",
  "gcp-data-access",
  "database-audit",
]);

/** Logs the source doesn't receive at all, so their absence says nothing. */
export const NotDeliveredGapSchema = z.strictObject({
  kind: z.literal("not-delivered"),
  log: NotDeliveredLogKindSchema,
  /** The service the log covers, when it's per service: `s3.amazonaws.com`, `storage.googleapis.com`. */
  service: nonEmpty.optional(),
  /** The anchor on the customer docs page that says how to turn this log on. */
  docsAnchor: nonEmpty.optional(),
  message: nonEmpty,
});

/** The window starts before the oldest entry the source keeps. */
export const RetentionGapSchema = z.strictObject({
  kind: z.literal("retention"),
  /** The oldest time the source still holds entries for. */
  retainedFrom: IsoTimestampSchema,
  message: nonEmpty,
});

/** The window reaches past what the source has ingested so far. */
export const LagGapSchema = z.strictObject({
  kind: z.literal("lag"),
  /** Entries are complete up to this time, when the source can say. */
  checkedThrough: IsoTimestampSchema.optional(),
  message: nonEmpty,
});

/** The source returned only part of the entries between `start` and `end`. */
export const TruncatedGapSchema = z.strictObject({
  kind: z.literal("truncated"),
  start: IsoTimestampSchema,
  end: IsoTimestampSchema,
  message: nonEmpty,
});

export const GapSchema = z.discriminatedUnion("kind", [
  NotDeliveredGapSchema,
  RetentionGapSchema,
  LagGapSchema,
  TruncatedGapSchema,
]);

/**
 * The `logs.read` input. `cursor` is the one a previous read returned, sent
 * back unchanged with the same `query`.
 *
 * `logGroupName` is the CloudTrail log group from the `aws-cloudwatch`
 * item's config. It is required for `source: "cloudtrail"` on that
 * connector and ignored elsewhere; it travels beside the query rather than in
 * it because the grant integration that builds the query doesn't know which
 * log-source item will serve it.
 */
export const LogReadInputSchema = z.strictObject({
  query: LogQuerySchema,
  cursor: nonEmpty.optional(),
  logGroupName: nonEmpty.optional(),
});

/**
 * The `logs.read` output.
 *
 * - `running`: the source is still working; call again with `cursor`. Entries may be empty.
 * - `more`: these entries are final, and there are more; call again with `cursor`.
 * - `done`: these are the last entries; there is no `cursor`.
 *
 * `checkedThrough` is the newest time the source has ingested through, when
 * it can say. Gaps may repeat across pages; the caller dedupes them.
 */
export const LogReadResultSchema = z
  .strictObject({
    entries: z.array(LogEntrySchema),
    cursor: nonEmpty.optional(),
    state: z.enum(["running", "more", "done"]),
    checkedThrough: IsoTimestampSchema.optional(),
    gaps: z.array(GapSchema),
  })
  .refine((r) => (r.state === "done") === (r.cursor === undefined), {
    message: "cursor must be set unless state is done",
  });

/**
 * The `logs.check` input: the same {@link LogQuerySchema} the read takes
 * (its `window` is ignored), so the connector can tell which services the
 * grant touches. `logGroupName` is as for {@link LogReadInputSchema}.
 */
export const LogCheckInputSchema = z.strictObject({
  target: LogQuerySchema,
  logGroupName: nonEmpty.optional(),
});

/** The `logs.check` output: only `not-delivered` gaps. */
export const LogCheckResultSchema = z.strictObject({
  gaps: z.array(NotDeliveredGapSchema),
});

export type LogWindow = z.infer<typeof LogWindowSchema>;
export type CloudTrailIdentity = z.infer<typeof CloudTrailIdentitySchema>;
export type CloudTrailLogQuery = z.infer<typeof CloudTrailLogQuerySchema>;
export type GcpAuditLogQuery = z.infer<typeof GcpAuditLogQuerySchema>;
export type DatabaseEngine = z.infer<typeof DatabaseEngineSchema>;
export type RdsLogQuery = z.infer<typeof RdsLogQuerySchema>;
export type CloudSqlLogQuery = z.infer<typeof CloudSqlLogQuerySchema>;
export type LogQuery = z.infer<typeof LogQuerySchema>;
export type LogSource = z.infer<typeof LogSourceSchema>;
export type LogEntry = z.infer<typeof LogEntrySchema>;
export type NotDeliveredLogKind = z.infer<typeof NotDeliveredLogKindSchema>;
export type NotDeliveredGap = z.infer<typeof NotDeliveredGapSchema>;
export type RetentionGap = z.infer<typeof RetentionGapSchema>;
export type LagGap = z.infer<typeof LagGapSchema>;
export type TruncatedGap = z.infer<typeof TruncatedGapSchema>;
export type Gap = z.infer<typeof GapSchema>;
export type LogReadInput = z.infer<typeof LogReadInputSchema>;
export type LogReadResult = z.infer<typeof LogReadResultSchema>;
export type LogCheckInput = z.infer<typeof LogCheckInputSchema>;
export type LogCheckResult = z.infer<typeof LogCheckResultSchema>;
