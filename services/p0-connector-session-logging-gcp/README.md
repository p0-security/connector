# p0-connector-session-logging-gcp

GCP Cloud Logging connector for Access Logs. It reads the Cloud Audit Log entries, and in phase 2
the Cloud SQL database audit entries, that P0 attributes to a request, straight from the customer's
own projects through `entries.list`. It grants nothing, and P0 stores none of what it reads.

Ships only as a Cloud Run container image, named `p0-connector-session-logging-gcp`, outside
any VPC. A `project` item's connector covers its project, and an `organization` item's connector
covers every project in the organization.

## Routes

- `gcp-cloud-logging.install.validation.get`: given `{ projectId }`, lists one Data Access entry
  from the last day. That needs `roles/logging.privateLogViewer`.
- `gcp-cloud-logging.logs.read` and `gcp-cloud-logging.logs.check`: the `logs` route from
  `@p0security/connector-core`. `check` has nothing to report for `gcp-audit`, because P0 reads
  whether Data Access logs are on itself.

## Reading

The connector builds the `entries.list` filter from the closed `LogQuery`, and no filter text
comes from P0. The filter selects the project's activity, data_access, system_event and policy
audit logs. It matches the principal, whether acting directly or impersonating a service account
(`serviceAccountDelegationInfo`), and the window. It also matches the permissions, unless they
would push the filter past Logging's length limit. The connector checks every entry again, with
the resource prefixes, before it returns the entry.

Pages hold 1,000 entries, oldest first, and the page token is the cursor. A call reads at most
three pages, so a read uses only a small share of the project's 60 reads a minute. On a 429 it
backs off, and when its 20-second budget runs out it returns what it has with `state: "more"`.

## Permissions

The service account needs `roles/logging.privateLogViewer` on the covered project or
organization.

## Database audit logs

A `cloudsql` query reads the instance's entries in the project's Data Access log (`resource.type`
`cloudsql_database`). These are pgAudit and MySQL audit records, matched on `request.user` or
`request.gcpIamAccount`, plus IAM logins (`cloudsql.instances.login`) by the query's IAM email. The
connector narrows them by database and by table, and keeps a record that names no table. P0 never
checks whether auditing is on, so `logs.check` returns nothing for `cloudsql`.
