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
 * (`p0v_*`), and the manager holds `ADMIN OPTION` on it.
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
        ELSE pg_has_role(current_user, r.oid, 'MEMBER WITH ADMIN OPTION')
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
 * The memberships of the role named `$1` that the manager granted, one row
 * for each role and grantor. From PostgreSQL 16 a membership's grantor is
 * the role whose `ADMIN OPTION` the `GRANT` used: the manager, or a role
 * whose privileges the manager inherits. Those are the memberships a
 * `REVOKE` by the manager removes, and no other. A role can be held through
 * several grantors at once, and a `REVOKE` that does not name the grantor
 * removes only the one PostgreSQL infers when it runs. That is not always
 * the one that exists: it only prints a warning and removes nothing.
 * `grantor` is therefore there from 16. Before 16 a role is held once,
 * whoever granted it, a plain `REVOKE` removes it, and `grantor` is `NULL`.
 */
export const MANAGER_GRANTED_ROLES_SQL = `SELECT r.rolname AS name,
    CASE WHEN current_setting('server_version_num')::int >= 160000
      THEN grantor.rolname END AS grantor
  FROM pg_auth_members m
    JOIN pg_roles r ON r.oid = m.roleid
    JOIN pg_roles member ON member.oid = m.member
    JOIN pg_roles grantor ON grantor.oid = m.grantor
  WHERE member.rolname = $1
    AND pg_has_role(current_user, m.grantor, 'USAGE')
  ORDER BY r.rolname COLLATE "C", grantor.rolname COLLATE "C"`;

// copy of `listDatabases` in services/p0-connector-pg/src/accesses/common/handler.ts,
// in a fixed order
export const DATABASES_SQL = `SELECT datname AS name FROM pg_database
  WHERE datistemplate = false ORDER BY datname COLLATE "C"`;

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

const managerGrants = z.array(
  z.object({ name: z.string(), grantor: z.string().nullable() })
);

/** A membership the manager granted: the role, and from PostgreSQL 16 the
 * role recorded as granting it. */
export type ManagerGrant = { role: string; grantor: string | null };

/**
 * The memberships of `login` that the manager granted. A role whose name is
 * not one a policy can hold is left out: the connector grants no such role,
 * so the membership is not the connector's to take away.
 */
export const listManagerGrants = async (
  query: PgQuery,
  login: string
): Promise<ManagerGrant[]> =>
  managerGrants
    .parse(await query(MANAGER_GRANTED_ROLES_SQL, [login]))
    .filter(({ name }) => isIdentifier(name))
    .map(({ name, grantor }) => ({ role: name, grantor }));

const loginRows = z
  .array(z.object({ canLogin: z.boolean(), connectionLimit: z.number().int() }))
  .max(1);

/** Whether the role named `login` can log in, and its connection limit, or
 * `undefined` when there is no such role. */
export const findLogin = async (query: PgQuery, login: string) =>
  loginRows.parse(await query(LOGIN_SQL, [login]))[0];

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
): Statement[] => [
  {
    template: hasGrantOptions
      ? "GRANT %I TO current_user WITH INHERIT TRUE"
      : "GRANT %I TO current_user",
    args: [login],
  },
  {
    template: hasGrantOptions
      ? "GRANT %I TO current_user WITH SET TRUE"
      : "GRANT %I TO current_user",
    args: [owner],
  },
  { template: "REASSIGN OWNED BY %I TO %I", args: [login, owner] },
];
