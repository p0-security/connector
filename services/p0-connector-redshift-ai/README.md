# p0-connector-redshift-ai

Redshift (AI) connector. It lets an agent in a P0 agentic session reach an Amazon Redshift
provisioned cluster or Serverless workgroup as a database user P0 creates for that grant
alone, `IAMR:p0-agent-<id>`, which the grant's own IAM role signs in as.

Ships only as an AWS Lambda container image, named `p0-connector-redshift-ai`, outside any
VPC.

## Authentication

The connector holds no secret. It reaches Redshift only through the Data API, in the
target's region, as its own execution role: it sends no `DbUser` and no secret, so the Data
API signs it in with `redshift:GetClusterCredentialsWithIAM` or
`redshift-serverless:GetCredentials`, as the database user `IAMR:<execution role name>`.

The customer makes that user an admin once, as a superuser:

```sql
CREATE USER "IAMR:<execution role>" PASSWORD DISABLE;
GRANT ROLE "sys:secadmin" TO "IAMR:<execution role>";
CREATE ROLE p0_connector_admin;
GRANT ALTER TABLE, DROP SCHEMA, DROP FUNCTION, DROP PROCEDURE TO ROLE p0_connector_admin;
GRANT ROLE p0_connector_admin TO "IAMR:<execution role>";
```

A superuser also works.

The connector acts only on users named `IAMR:p0-agent-<id>` and roles named `p0_agent_<id>`
(see `src/sql.ts`). The Data API takes no identifier as a parameter, so every name is checked
against a pattern and quoted, and every string literal is escaped.

## Install validation

`redshift-ai.install.validation.get` is what install validation runs, every hour, so it
never writes. It runs these checks in order, and a failure names its step in
`payload.step`:

1. `target`: the execution role finds the cluster (`redshift:DescribeClusters`) or workgroup
   (`redshift-serverless:GetWorkgroup`). Returns its ARN.
2. `sign_in`: the execution role runs a statement through the Data API.
3. `admin_roles`: the connector's user is a superuser, or holds `sys:secadmin` and the
   `ALTER TABLE`, `DROP SCHEMA`, `DROP FUNCTION` and `DROP PROCEDURE` system permissions,
   itself or through a role granted to it directly.
4. `object_owner`: when the install names an object owner, that user exists.

Then it returns two kinds of warning, which don't fail the install:

- `grantable_objects`: the connector's user owns no table or view in the install's database
  and holds `WITH GRANT OPTION` on none, so objects access has nothing to grant.
- `public_create`: one per database where PUBLIC can still create in the `public` schema.
