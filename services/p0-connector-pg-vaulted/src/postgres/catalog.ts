import { z } from "zod";

import { ident, isIdentifier } from "../identifier.ts";
import type { PgQuery } from "./client.ts";

/** The trivial statement that proves a sign-in. */
export const PING_SQL = "SELECT 1";

/** Whether the manager can create roles. */
export const CAN_CREATE_ROLE_SQL = `SELECT rolcreaterole OR rolsuper AS allowed
  FROM pg_roles WHERE rolname = current_user`;

/**
 * Whether the manager can end other logins' sessions. `USAGE`, not `MEMBER`:
 * from PostgreSQL 16 a membership granted `WITH INHERIT FALSE` does not let
 * its member signal a backend.
 */
export const CAN_SIGNAL_BACKEND_SQL = `SELECT rolsuper
    OR pg_has_role(current_user, 'pg_signal_backend', 'USAGE') AS allowed
  FROM pg_roles WHERE rolname = current_user`;

/** Whether `GRANT` takes `WITH INHERIT` and `WITH SET`, which PostgreSQL 16
 * added. */
export const HAS_GRANT_OPTIONS_SQL = `SELECT
  current_setting('server_version_num')::int >= 160000 AS allowed`;

/**
 * The grantable roles: the roles that cannot log in, are not superuser, are
 * not PostgreSQL's or RDS's own (`pg_*`, `rds*`), are not grant logins
 * (`p0v_*`), and that the manager holds `ADMIN OPTION` on.
 *
 * From PostgreSQL 16 the manager can use an `ADMIN OPTION` that it, or a role
 * whose privileges it inherits, holds. `pg_has_role(..., 'MEMBER WITH ADMIN
 * OPTION')` is not that test: it is also true for an `ADMIN OPTION` reached
 * through a membership the manager does not inherit, which `GRANT` refuses.
 * Before 16 it is that test. There `CREATEROLE` alone would let the manager
 * grant any role that is not superuser, but the connector offers only the
 * roles the manager was given `ADMIN OPTION` on, so that the customer chooses
 * the grantable roles the same way on every version. A superuser can grant
 * any role.
 */
export const GRANTABLE_ROLES_SQL = `SELECT r.rolname AS name
  FROM pg_roles r,
    (SELECT rolsuper FROM pg_roles WHERE rolname = current_user) me
  WHERE NOT r.rolcanlogin
    AND NOT r.rolsuper
    AND r.rolname !~ '^(pg_|rds|p0v_)'
    AND (
      me.rolsuper
      OR CASE WHEN current_setting('server_version_num')::int >= 160000
        THEN EXISTS (
          SELECT 1 FROM pg_auth_members m
          WHERE m.roleid = r.oid AND m.admin_option
            AND pg_has_role(current_user, m.member, 'USAGE'))
        ELSE pg_has_role(current_user, r.oid, 'MEMBER WITH ADMIN OPTION')
        END
    )
  ORDER BY r.rolname COLLATE "C"`;

// copy of `listDatabases` in services/p0-connector-pg/src/accesses/common/handler.ts,
// in a fixed order
export const DATABASES_SQL = `SELECT datname AS name FROM pg_database
  WHERE datistemplate = false ORDER BY datname COLLATE "C"`;

const names = z.array(z.object({ name: z.string() }));
const answer = z.tuple([z.object({ allowed: z.boolean() })]);

/** The answer to one of the yes-or-no statements above. */
export const holds = async (query: PgQuery, sql: string) =>
  answer.parse(await query(sql))[0].allowed;

/**
 * The grantable roles, by name. A role whose name is not one a policy can
 * hold is left out, because no grant can be approved for it.
 */
export const listGrantableRoles = async (query: PgQuery) =>
  names
    .parse(await query(GRANTABLE_ROLES_SQL))
    .map(({ name }) => name)
    .filter(isIdentifier);

export const listDatabases = async (query: PgQuery) =>
  names.parse(await query(DATABASES_SQL)).map(({ name }) => name);

/**
 * The statements that hand what `login` owns in the connected database to
 * `owner`. `REASSIGN OWNED` needs the manager to hold the privileges of
 * `login`, and those of `owner` (before PostgreSQL 16) or the right to
 * `SET ROLE` to it (from 16). The manager grants itself both first, which a
 * grantable `owner` and a login it created allow. The README has what each
 * version requires, as measured, under Manager privileges.
 */
export const reassignOwnedStatements = (
  login: string,
  owner: string,
  hasGrantOptions: boolean
) => [
  `GRANT ${ident(login)} TO current_user${hasGrantOptions ? " WITH INHERIT TRUE" : ""}`,
  `GRANT ${ident(owner)} TO current_user${hasGrantOptions ? " WITH SET TRUE" : ""}`,
  `REASSIGN OWNED BY ${ident(login)} TO ${ident(owner)}`,
];
