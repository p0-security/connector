import {
  ConnectorError,
  type ConnectorErrorOptions,
} from "@p0security/connector-core";

import {
  IS_GRANTABLE_ROLE_SQL,
  findLogin,
  holds,
  listManagerGrantedRoles,
} from "./postgres/catalog.ts";
import type { PgQuery } from "./postgres/client.ts";
import { execute } from "./postgres/statement.ts";

/**
 * The one state a grant login is in. It is read from the catalog on each
 * call and stored nowhere else:
 *
 * - `absent`: no role has the login's name.
 * - `prepared`: the role cannot log in, and has no connection limit.
 * - `active`: the role can log in.
 * - `retired`: the role cannot log in, and has a connection limit. The
 *   database cutoff sets the limit to 0, which nothing clears.
 */
export type GrantLoginState = "absent" | "active" | "prepared" | "retired";

/** `rolconnlimit` of a role with no connection limit. */
const NO_CONNECTION_LIMIT = -1;

/**
 * The state of the grant login named `login`. A role that cannot log in
 * counts as prepared only as `createUser` leaves it, with no connection
 * limit: any limit marks it retired, so that a role nobody prepared is never
 * activated.
 */
export const readGrantLoginState = async (
  query: PgQuery,
  login: string
): Promise<GrantLoginState> => {
  const role = await findLogin(query, login);
  if (!role) return "absent";
  if (role.canLogin) return "active";
  return role.connectionLimit === NO_CONNECTION_LIMIT ? "prepared" : "retired";
};

type Refusal = Pick<ConnectorErrorOptions, "message" | "type">;

/** What a primitive does to a grant login in one state: the template of the
 * statement it runs, or why it refuses. */
type Step = { refuse: Refusal } | { template: string };

const NOT_FOUND: Refusal = {
  type: "object_not_found",
  message: "The grant login does not exist in PostgreSQL.",
};

const IN_USE: Refusal = {
  type: "dependency_violation",
  message:
    "The grant login can already log in, so the connector will not set its password again.",
};

const RETIRED: Refusal = {
  type: "dependency_violation",
  message:
    "The grant login is retired. A retired login is never given a password or activated again.",
};

const ACTIVATE = "ALTER ROLE %I LOGIN VALID UNTIL %L";

/**
 * The grant login's lifecycle: what `createUser` (`prepare`) and
 * `setPoliciesForUser` with policies (`activate`) do in each state.
 * `prepare` takes the login, its password's verifier and the deadline, and
 * `activate` the login and the deadline.
 *
 * A prepared login gets a new password, because nobody can have used the
 * old one. No template here clears a connection limit.
 */
const LIFECYCLE: Record<GrantLoginState, { prepare: Step; activate: Step }> = {
  absent: {
    prepare: { template: "CREATE ROLE %I NOLOGIN PASSWORD %L VALID UNTIL %L" },
    activate: { refuse: NOT_FOUND },
  },
  prepared: {
    prepare: { template: "ALTER ROLE %I PASSWORD %L VALID UNTIL %L" },
    activate: { template: ACTIVATE },
  },
  active: {
    prepare: { refuse: IN_USE },
    activate: { template: ACTIVATE },
  },
  retired: {
    prepare: { refuse: RETIRED },
    activate: { refuse: RETIRED },
  },
};

/** The template `primitive` runs on `login` in `state`. It throws when the
 * primitive refuses the state. */
const templateFor = (
  primitive: "activate" | "prepare",
  state: GrantLoginState,
  login: string
) => {
  const step = LIFECYCLE[state][primitive];
  if ("refuse" in step) {
    throw new ConnectorError({ ...step.refuse, payload: { login, state } });
  }
  return step.template;
};

/**
 * Prepares the grant login: it exists, cannot log in, and has the password
 * of `verifier`, the deadline and the comment. Returns the state it was in.
 * It is to run in one transaction.
 */
export const prepareGrantLogin = async (
  query: PgQuery,
  grant: { login: string; verifier: string; deadline: string; comment: string }
) => {
  const { login, verifier, deadline, comment } = grant;
  const from = await readGrantLoginState(query, login);
  const template = templateFor("prepare", from, login);
  await execute(query, { template, args: [login, verifier, deadline] });
  await execute(query, {
    template: "COMMENT ON ROLE %I IS %L",
    args: [login, comment],
  });
  return from;
};

/**
 * Makes the roles the manager granted the grant login equal `roles`, then
 * activates the login until the deadline. It leaves the login's password,
 * and any membership the manager did not grant, as they are. Returns the
 * state the login was in and the roles it granted and revoked. It is to run
 * in one transaction.
 */
export const activateGrantLogin = async (
  query: PgQuery,
  grant: { login: string; roles: string[]; deadline: string }
) => {
  const { login, roles, deadline } = grant;
  const from = await readGrantLoginState(query, login);
  const template = templateFor("activate", from, login);
  for (const role of roles) {
    if (!(await holds(query, IS_GRANTABLE_ROLE_SQL, [role]))) {
      throw new ConnectorError({
        type: "validation_error",
        message: `The role ${role} is not a grantable role of this target.`,
        payload: { login, rolename: role },
      });
    }
  }
  const held = await listManagerGrantedRoles(query, login);
  const granted = roles.filter((role) => !held.includes(role));
  const revoked = held.filter((role) => !roles.includes(role));
  for (const role of granted) {
    await execute(query, { template: "GRANT %I TO %I", args: [role, login] });
  }
  for (const role of revoked) {
    await execute(query, {
      template: "REVOKE %I FROM %I",
      args: [role, login],
    });
  }
  await execute(query, { template, args: [login, deadline] });
  return { from, granted, revoked };
};
