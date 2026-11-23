import {
  ConnectorError,
  type ConnectorErrorOptions,
} from "@p0security/connector-core";

import {
  HAS_GRANT_OPTIONS_SQL,
  IS_GRANTABLE_ROLE_SQL,
  countSessions,
  endSessions,
  findLogin,
  holds,
  listManagerGrantedRoles,
  reassignOwnedStatement,
  takePrivilegesStatement,
} from "./postgres/catalog.ts";
import type { PgQuery, PgSession } from "./postgres/client.ts";
import { type Statement, execute } from "./postgres/statement.ts";

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

const NOT_CUT_OFF: Refusal = {
  type: "dependency_violation",
  message:
    "The grant login has not been cut off. The connector drops a login only after its database cutoff.",
};

const ACTIVATE = "ALTER ROLE %I LOGIN VALID UNTIL %L";

const REVOKE = "REVOKE %I FROM %I";

const RETIRE = "ALTER ROLE %I NOLOGIN CONNECTION LIMIT 0 PASSWORD NULL";

/** There is no login, so the primitive has no statement to run. */
const NOTHING = "nothing";

/**
 * The grant login's lifecycle: what `createUser` (`prepare`),
 * `setPoliciesForUser` with policies (`activate`), `setPoliciesForUser` with
 * none (`retire`) and `deleteUser` (`drop`) do in each state. `prepare` takes
 * the login, its password's verifier and the deadline, `activate` the login
 * and the deadline, and `retire` and `drop` the login.
 *
 * A prepared login gets a new password, because nobody can have used the
 * old one. No template here clears a connection limit, and only `retire`
 * sets one, so a login is dropped only after its cutoff.
 */
const LIFECYCLE: Record<
  GrantLoginState,
  {
    prepare: Step;
    activate: Step;
    retire: Step | typeof NOTHING;
    drop: Step | typeof NOTHING;
  }
> = {
  absent: {
    prepare: { template: "CREATE ROLE %I NOLOGIN PASSWORD %L VALID UNTIL %L" },
    activate: { refuse: NOT_FOUND },
    retire: NOTHING,
    drop: NOTHING,
  },
  prepared: {
    prepare: { template: "ALTER ROLE %I PASSWORD %L VALID UNTIL %L" },
    activate: { template: ACTIVATE },
    retire: { template: RETIRE },
    drop: { refuse: NOT_CUT_OFF },
  },
  active: {
    prepare: { refuse: IN_USE },
    activate: { template: ACTIVATE },
    retire: { template: RETIRE },
    drop: { refuse: NOT_CUT_OFF },
  },
  retired: {
    prepare: { refuse: RETIRED },
    activate: { refuse: RETIRED },
    retire: { template: RETIRE },
    drop: { template: "DROP ROLE %I" },
  },
};

/** The template of `step`, which a primitive runs on `login` in `state`. It
 * throws when the step is a refusal. */
const templateOf = (step: Step, state: GrantLoginState, login: string) => {
  if ("refuse" in step) {
    throw new ConnectorError({ ...step.refuse, payload: { login, state } });
  }
  return step.template;
};

/** Throws unless `role` is a grantable role, by the rule `list` offers roles
 * by. */
const requireGrantable = async (
  query: PgQuery,
  login: string,
  role: string
) => {
  if (await holds(query, IS_GRANTABLE_ROLE_SQL, [role])) return;
  throw new ConnectorError({
    type: "validation_error",
    message: `The role ${role} is not a grantable role of this target.`,
    payload: { login, rolename: role },
  });
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
  const template = templateOf(LIFECYCLE[from].prepare, from, login);
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
  const template = templateOf(LIFECYCLE[from].activate, from, login);
  for (const role of roles) await requireGrantable(query, login, role);
  const held = await listManagerGrantedRoles(query, login);
  const granted = roles.filter((role) => !held.includes(role));
  const revoked = held.filter((role) => !roles.includes(role));
  for (const role of granted) {
    await execute(query, { template: "GRANT %I TO %I", args: [role, login] });
  }
  for (const role of revoked) {
    await execute(query, { template: REVOKE, args: [role, login] });
  }
  await execute(query, { template, args: [login, deadline] });
  return { from, granted, revoked };
};

/** How many times the cutoff ends and counts a login's sessions before it
 * gives up, and how long it waits between two of those looks. */
const SESSION_LOOKS = 10;
const SESSION_LOOK_WAIT_MS = 200;

/**
 * Ends the sessions of the grant login until none is left, and returns how
 * many it ended. The login must already be unable to sign in.
 *
 * A sign-in that PostgreSQL let in just before the login was disabled shows
 * among the sessions a few milliseconds later. So every look ends what it
 * finds, and the first look alone never confirms that none is left. When
 * some outlive the last look, it throws, so that the call is tried again.
 */
export const endGrantLoginSessions = async (
  query: PgQuery,
  login: string,
  wait: (ms: number) => Promise<void>
) => {
  const ended = new Set<number>();
  let sessions = 0;
  for (let look = 1; look <= SESSION_LOOKS; look++) {
    if (look > 1) await wait(SESSION_LOOK_WAIT_MS);
    for (const pid of await endSessions(query, login)) ended.add(pid);
    sessions = await countSessions(query, login);
    if (sessions === 0 && look > 1) return ended.size;
  }
  throw new ConnectorError({
    type: "upstream_unavailable",
    message:
      "The grant login is disabled, but some of its sessions have not ended yet. Try again in a moment.",
    payload: { login, sessions },
  });
};

/**
 * The database cutoff of the grant login. Each step is safe to repeat:
 *
 * 1. In one transaction, the login is retired, which disables it and clears
 *    its password, and loses every membership the manager granted it.
 * 2. Its sessions are ended. The transaction is committed first, so that
 *    PostgreSQL refuses a new sign-in while the old sessions go.
 * 3. Its sessions are counted, as {@link endGrantLoginSessions} does. When
 *    some outlive the last count, it throws, so that the cutoff is tried
 *    again. The login stays retired.
 *
 * Returns the state the login was in, the roles it lost and how many
 * sessions it ended. With no login it changes nothing.
 */
export const retireGrantLogin = async (
  { query, committed }: PgSession,
  login: string,
  wait: (ms: number) => Promise<void>
) => {
  const from = await readGrantLoginState(query, login);
  const step = LIFECYCLE[from].retire;
  if (step === NOTHING) return { from, revoked: [], sessionsEnded: 0 };
  const template = templateOf(step, from, login);
  const revoked = await committed(async (inTransaction) => {
    await execute(inTransaction, { template, args: [login] });
    const held = await listManagerGrantedRoles(inTransaction, login);
    for (const role of held) {
      await execute(inTransaction, { template: REVOKE, args: [role, login] });
    }
    return held;
  });
  const sessionsEnded = await endGrantLoginSessions(query, login, wait);
  return { from, revoked, sessionsEnded };
};

/**
 * What the cleanup is to do with the grant login, which it reads and does
 * not change: the state the login is in, and the statement that drops it,
 * or none when there is no login. It throws for a login that has not been
 * cut off, and for an `owner` that is not a grantable role.
 */
export const readCleanup = async (
  query: PgQuery,
  grant: { login: string; owner: string }
): Promise<{ from: GrantLoginState; drop?: Statement }> => {
  const { login, owner } = grant;
  const from = await readGrantLoginState(query, login);
  const step = LIFECYCLE[from].drop;
  if (step === NOTHING) return { from };
  const template = templateOf(step, from, login);
  await requireGrantable(query, login, owner);
  return { from, drop: { template, args: [login] } };
};

/**
 * Gives the manager the privileges of the grant login, which handing over
 * and dropping what the login owns need in every database.
 */
export const takeGrantLoginPrivileges = async (query: PgQuery, login: string) =>
  execute(
    query,
    takePrivilegesStatement(login, await holds(query, HAS_GRANT_OPTIONS_SQL))
  );

/**
 * Hands what the grant login owns in the connected database to `owner`,
 * then drops the privileges it was granted there, so that nothing in the
 * database depends on the login. It is to run in one transaction.
 */
export const handOverOwned = async (
  query: PgQuery,
  grant: { login: string; owner: string }
) => {
  const { login, owner } = grant;
  await execute(query, reassignOwnedStatement(login, owner));
  await execute(query, { template: "DROP OWNED BY %I", args: [login] });
};
