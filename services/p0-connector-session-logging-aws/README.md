# p0-connector-session-logging-aws

AWS CloudWatch Logs connector for Access Logs. It reads the CloudTrail events, and in phase 2
the RDS database audit logs, that P0 attributes to a request, from the customer's own
CloudWatch Logs. It grants nothing, and P0 stores none of what it reads.

Ships only as an AWS Lambda container image, named `p0-connector-session-logging-aws`, outside
any VPC. One connector serves one `aws-cloudwatch` item: one account and region.

## Routes

- `aws-cloudwatch.install.validation.get`: given the item's `{ logGroupName?, coverage? }`,
  checks that the CloudTrail log group exists, holds an event from the last 24 hours, and gets
  an organization trail when `coverage` is `organization`. It also reports which data events
  the trail delivers. Missing data events are a warning, never a failure.
- `aws-cloudwatch.logs.read` and `aws-cloudwatch.logs.check`: the `logs` route from
  `@p0security/connector-core`. A `cloudtrail` query needs `logGroupName`, the item's CloudTrail
  group.

## Reading

The connector builds a Logs Insights query from the closed `LogQuery`, and no query text comes
from P0. The account, the identity and, where the service is known, `eventSource` go into that
query. The connector checks every row against the full query again, with the action and
resource patterns, before it returns the row. Insights returns at most 10,000 rows. When a
time slice comes back full, the connector splits the slice in half and reads each half. It
stops splitting at one minute and reports `truncated` instead.

A read polls for up to 20 seconds. If the query is still running, it returns
`state: "running"` with a cursor. The cursor holds the query IDs and the slices left to read,
and it's bound to the query, so it can't be used with any other.

## Permissions

The execution role needs, on the CloudTrail group and `/aws/rds/*` in its account and region:
`logs:StartQuery`, `logs:GetQueryResults`, `logs:StopQuery` and `logs:DescribeLogGroups`. For
the trail checks it also needs `cloudtrail:DescribeTrails` and `cloudtrail:GetEventSelectors`.

## Database audit logs

An `rds` query reads the log group RDS exports the engine's audit log to:
`/aws/rds/instance/<id>/postgresql` or `/audit`, and `/aws/rds/cluster/<id>/…` for Aurora. The
query names the group, so these reads don't use `logGroupName`. For Postgres, the connector reads
pgaudit `AUDIT:` lines and takes the user and database from the `%u@%d` part of RDS's
`log_line_prefix`. For MySQL, it reads the audit plugin's CSV records. Rows are matched on the
database user, and on the database and tables when the query names them. A statement that names no
table is kept. A missing log group means auditing or log export is off, and the read returns a
`not-delivered` gap that says "No database logs found for this instance." P0 never checks whether
auditing is on, so `logs.check` returns nothing for `rds`.
