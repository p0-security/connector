import { z } from "zod";

import { isIdentifier } from "../identifier.ts";
import type { PgQuery } from "./client.ts";
import type { Statement } from "./statement.ts";

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
 * What makes a role `r` grantable: it cannot log in, is not superuser, is
 * not PostgreSQL's or RDS's own (`pg_*`, `rds*`), is not a grant login
 * (`p0v_*`), the manager holds `ADMIN OPTION` on it, and the manager can
 * hand a grant login's objects to it.
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
 *
 * `REASSIGN OWNED BY <grant login> TO r` needs the manager to be able to
 * `SET ROLE` to `r` from PostgreSQL 16, and to hold the privileges of `r`
 * before. The rule asks for that of the grants the customer made, so that
 * the connector never grants the manager a role to make up for it. The `CASE`
 * keeps `'SET'` from a server before 16, which does not know it.
 */
const GRANTABLE_ROLE = `FROM pg_roles r,
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
          AND pg_has_role(current_user, r.oid, 'SET')
        ELSE pg_has_role(current_user, r.oid, 'MEMBER WITH ADMIN OPTION')
          AND pg_has_role(current_user, r.oid, 'USAGE')
        END
    )`;

/** The grantable roles. */
export const GRANTABLE_ROLES_SQL = `SELECT r.rolname AS name
  ${GRANTABLE_ROLE}
  ORDER BY r.rolname COLLATE "C"`;

/** Whether the role named `$1` is grantable, by the rule `list` offers
 * roles by. */
export const IS_GRANTABLE_ROLE_SQL = `SELECT EXISTS (
  SELECT 1 ${GRANTABLE_ROLE}
    AND r.rolname = $1) AS allowed`;

/** What tells a grant login's state: whether the role named `$1` can log
 * in, and its connection limit. No row when there is no such role. */
export const LOGIN_SQL = `SELECT rolcanlogin AS "canLogin",
    rolconnlimit AS "connectionLimit"
  FROM pg_roles WHERE rolname = $1`;

/**
 * The roles that the role named `$1` is a member of by the manager's grant.
 * From PostgreSQL 16 a membership's grantor is the role whose `ADMIN OPTION`
 * the `GRANT` used: the manager, or a role whose privileges the manager
 * inherits. Those are the memberships a `REVOKE` by the manager removes, and
 * no other. Before 16 the grantor is the login that ran the `GRANT`.
 */
export const MANAGER_GRANTED_ROLES_SQL = `SELECT r.rolname AS name
  FROM pg_auth_members m
    JOIN pg_roles r ON r.oid = m.roleid
    JOIN pg_roles member ON member.oid = m.member
  WHERE member.rolname = $1
    AND pg_has_role(current_user, m.grantor, 'USAGE')
  GROUP BY r.rolname
  ORDER BY r.rolname COLLATE "C"`;

// copy of `listDatabases` in services/p0-connector-pg/src/accesses/common/handler.ts,
// in a fixed order
export const DATABASES_SQL = `SELECT datname AS name FROM pg_database
  WHERE datistemplate = false ORDER BY datname COLLATE "C"`;

/**
 * The databases the cleanup hands a grant login's objects over in: every
 * one the manager can connect to. Never `rdsadmin`, which is RDS's own.
 */
export const CONNECTABLE_DATABASES_SQL = `SELECT datname AS name
  FROM pg_database
  WHERE NOT datistemplate
    AND datallowconn
    AND has_database_privilege(current_user, oid, 'CONNECT')
    AND datname <> 'rdsadmin'
  ORDER BY datname COLLATE "C"`;

/** Ends every session of the login named `$1`: one row for each session it
 * signalled, with the session's backend. The connector's own session is the
 * manager's. */
export const END_SESSIONS_SQL = `SELECT pid, pg_terminate_backend(pid) AS ended
  FROM pg_stat_activity
  WHERE usename = $1 AND pid <> pg_backend_pid()`;

/** How many sessions the login named `$1` has. A session that was signalled
 * is counted until its backend has exited. */
export const COUNT_SESSIONS_SQL = `SELECT count(*)::int AS sessions
  FROM pg_stat_activity
  WHERE usename = $1 AND pid <> pg_backend_pid()`;

const names = z.array(z.object({ name: z.string() }));
const answer = z.tuple([z.object({ allowed: z.boolean() })]);

/** The answer to one of the yes-or-no statements above. */
export const holds = async (
  query: PgQuery,
  sql: string,
  bindings?: readonly string[]
) => answer.parse(await query(sql, bindings))[0].allowed;

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

export const listConnectableDatabases = async (query: PgQuery) =>
  names.parse(await query(CONNECTABLE_DATABASES_SQL)).map(({ name }) => name);

const signalled = z.array(
  z.object({ pid: z.number().int(), ended: z.boolean() })
);
const sessionCount = z.tuple([z.object({ sessions: z.number().int() })]);

/** Signals every session of `login` to end, and returns the backend of each
 * one it signalled. A signalled session takes a moment to go. */
export const endSessions = async (query: PgQuery, login: string) =>
  signalled.parse(await query(END_SESSIONS_SQL, [login])).map(({ pid }) => pid);

export const countSessions = async (query: PgQuery, login: string) =>
  sessionCount.parse(await query(COUNT_SESSIONS_SQL, [login]))[0].sessions;

/**
 * The roles `login` is a member of by the manager's grant. A role whose
 * name is not one a policy can hold is left out: the connector grants no
 * such role, so the membership is not the connector's to take away.
 */
export const listManagerGrantedRoles = async (query: PgQuery, login: string) =>
  names
    .parse(await query(MANAGER_GRANTED_ROLES_SQL, [login]))
    .map(({ name }) => name)
    .filter(isIdentifier);

const loginRows = z
  .array(z.object({ canLogin: z.boolean(), connectionLimit: z.number().int() }))
  .max(1);

/** Whether the role named `login` can log in, and its connection limit, or
 * `undefined` when there is no such role. */
export const findLogin = async (query: PgQuery, login: string) =>
  loginRows.parse(await query(LOGIN_SQL, [login]))[0];

/**
 * The statement by which the manager takes the privileges of `login`, which
 * `REASSIGN OWNED` and `DROP OWNED` need. From PostgreSQL 16 it says
 * `WITH INHERIT TRUE`, because the membership a role's creator gets is not
 * inherited. It is the only grant the connector makes to the manager, and it
 * goes when the login is dropped. Run again, it changes nothing.
 */
export const takePrivilegesStatement = (
  login: string,
  hasGrantOptions: boolean
): Statement => ({
  template: hasGrantOptions
    ? "GRANT %I TO current_user WITH INHERIT TRUE"
    : "GRANT %I TO current_user",
  args: [login],
});

/**
 * The statement that hands what `login` owns in the connected database to
 * `owner`. The manager needs the privileges of `login`, and what makes
 * `owner` a grantable role. The README has what each version requires, as
 * measured, under Manager privileges.
 */
export const reassignOwnedStatement = (
  login: string,
  owner: string
): Statement => ({
  template: "REASSIGN OWNED BY %I TO %I",
  args: [login, owner],
});
