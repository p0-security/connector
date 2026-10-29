import type { Field } from "@aws-sdk/client-redshift-data";

import type { InstallContext } from "../context.ts";

export const install: InstallContext = {
  target: { type: "serverless", name: "analytics" },
  region: "us-west-2",
  database: "dev",
};

export const provisioned: InstallContext = {
  ...install,
  target: { type: "provisioned", name: "analytics" },
};

type Row = Record<string, boolean | number | string | null>;

/** An answer to one statement: rows, or Redshift's error text. */
type Answer = Row[] | { error: string };

const toField = (value: Row[string]): Field =>
  value === null
    ? { isNull: true }
    : typeof value === "string"
      ? { stringValue: value }
      : typeof value === "number"
        ? { longValue: value }
        : { booleanValue: value };

/**
 * A Redshift Data API client that settles each statement on its first
 * `DescribeStatement`. `on` answers a statement, matched by a prefix of its
 * text or by a pattern, latest first; an answer of `undefined` passes the
 * statement to the next match, and a statement nothing answers finishes with
 * no rows. A batch
 * fails on its first statement that answers an error. `calls` records each
 * command's name and input, and `statements` each statement's SQL.
 */
export const fakeDataApi = () => {
  const calls: { command: string; input: Record<string, unknown> }[] = [];
  const statements: { sql: string; database: unknown }[] = [];
  const answers: {
    match: RegExp | string;
    answer: (sql: string, database: unknown) => Answer | undefined;
  }[] = [];
  const running = new Map<string, Answer>();
  let next = 0;

  const answerFor = (sql: string, database: unknown): Answer => {
    for (const { match, answer } of answers) {
      const matches =
        typeof match === "string" ? sql.startsWith(match) : match.test(sql);
      const result = matches ? answer(sql, database) : undefined;
      if (result !== undefined) return result;
    }
    return [];
  };

  const send = async (command: { input: Record<string, unknown> }) => {
    const name = command.constructor.name;
    const { input } = command;
    calls.push({ command: name, input });
    switch (name) {
      case "ExecuteStatementCommand": {
        const id = `s${++next}`;
        statements.push({ sql: input.Sql as string, database: input.Database });
        running.set(id, answerFor(input.Sql as string, input.Database));
        return { Id: id };
      }
      case "BatchExecuteStatementCommand": {
        const id = `b${++next}`;
        const sqls = input.Sqls as string[];
        let failure: Answer | undefined;
        for (const sql of sqls) {
          statements.push({ sql, database: input.Database });
          const answer = answerFor(sql, input.Database);
          if ("error" in answer) {
            failure = answer;
            break;
          }
        }
        running.set(id, failure ?? []);
        return { Id: id };
      }
      case "DescribeStatementCommand": {
        const answer = running.get(input.Id as string)!;
        return "error" in answer
          ? { Status: "FAILED", Error: answer.error }
          : { Status: "FINISHED", HasResultSet: answer.length > 0 };
      }
      case "GetStatementResultCommand": {
        const rows = running.get(input.Id as string) as Row[];
        const columns = Object.keys(rows[0] ?? {});
        return {
          ColumnMetadata: columns.map((name) => ({ name })),
          Records: rows.map((row) =>
            columns.map((column) => toField(row[column]!))
          ),
        };
      }
      default:
        return {};
    }
  };

  return {
    client: { send } as never,
    calls,
    statements,
    on: (
      match: RegExp | string,
      answer: (sql: string, database: unknown) => Answer | undefined
    ) => {
      answers.unshift({ match, answer });
    },
  };
};

export const AGENT = "IAMR:p0-agent-r1";
export const PRIVILEGE_ROLE = "p0_agent_r1";
export const CONNECTOR_USER = "IAMR:p0-connector-redshift-ai";

type Catalog = {
  databases: string[];
  users: Set<string>;
  roles: Set<string>;
  /** Roles granted to the agent. Only the connector's grants can be revoked
   * by the connector. */
  userGrants: { role: string; byConnector: boolean }[];
  /** What the agent owns. */
  relations: { database: string; schema: string; name: string }[];
  routines: {
    database: string;
    schema: string;
    name: string;
    args: string;
    kind: "f" | "p";
  }[];
  schemas: { database: string; name: string; objects: number }[];
  relationPrivileges: {
    database: string;
    schema: string;
    relation: string;
    identity: string;
    byConnector: boolean;
  }[];
  schemaPrivileges: {
    database: string;
    schema: string;
    identity: string;
    byConnector: boolean;
  }[];
};

const literals = (sql: string) =>
  [...sql.matchAll(/'([^']*)'/g)].map((match) => match[1]!);

const quoted = (sql: string) =>
  [...sql.matchAll(/"([^"]*)"/g)].map((match) => match[1]!);

/**
 * A Redshift catalog behind `api`: the reads the connector makes answer from
 * it, and its writes change it. A `REVOKE` of something the connector didn't
 * grant succeeds and changes nothing, as Redshift's does.
 */
export const fakeCatalog = (
  api: ReturnType<typeof fakeDataApi>,
  seed: Partial<Catalog> = {}
) => {
  const c: Catalog = {
    databases: ["dev"],
    users: new Set(),
    roles: new Set(),
    userGrants: [],
    relations: [],
    routines: [],
    schemas: [],
    relationPrivileges: [],
    schemaPrivileges: [],
    ...seed,
  };
  const on = api.on;

  on("SHOW DATABASES", () =>
    c.databases.map((name) => ({
      database_name: name,
      database_type: "local",
    }))
  );
  on("SELECT current_user", () => [{ user_name: CONNECTOR_USER }]);

  on(/FROM svv_user_info/, (sql) =>
    c.users.has(literals(sql)[0]!) ? [{ user_name: literals(sql)[0]! }] : []
  );
  on(/^CREATE USER/, (sql) => {
    const [user] = quoted(sql);
    if (c.users.has(user!))
      return { error: `ERROR: user "${user}" already exists` };
    c.users.add(user!);
    return [];
  });
  on(/^DROP USER IF EXISTS/, (sql) => {
    c.users.delete(quoted(sql)[0]!);
    return [];
  });
  on(/FROM svv_roles/, (sql) =>
    c.roles.has(literals(sql)[0]!) ? [{ role_name: literals(sql)[0]! }] : []
  );
  on(/^CREATE ROLE/, (sql) => {
    c.roles.add(quoted(sql)[0]!);
    return [];
  });
  on(/^DROP ROLE/, (sql) => {
    c.roles.delete(quoted(sql)[0]!);
    return [];
  });

  on(/FROM svv_user_grants/, () =>
    c.userGrants.map(({ role }) => ({ role_name: role }))
  );
  on(/^GRANT ROLE/, (sql) => {
    const [role] = quoted(sql);
    if (!c.userGrants.some((grant) => grant.role === role))
      c.userGrants.push({ role: role!, byConnector: true });
    return [];
  });
  on(/^REVOKE ROLE/, (sql) => {
    const [role] = quoted(sql);
    c.userGrants = c.userGrants.filter(
      (grant) => grant.role !== role || !grant.byConnector
    );
    return [];
  });

  on(/FROM pg_class c JOIN/, (_sql, database) =>
    c.relations
      .filter((relation) => relation.database === database)
      .map(({ schema, name }) => ({ schema_name: schema, name }))
  );
  on(/^ALTER TABLE .* OWNER TO/, (sql, database) => {
    const [schema, name] = quoted(sql);
    c.relations = c.relations.filter(
      (relation) =>
        !(
          relation.database === database &&
          relation.schema === schema &&
          relation.name === name
        )
    );
    return [];
  });

  on(/FROM pg_proc_info/, (_sql, database) =>
    c.routines
      .filter((routine) => routine.database === database)
      .map(({ schema, name, args, kind }) => ({
        schema_name: schema,
        name,
        args,
        kind,
      }))
  );
  on(/^DROP (FUNCTION|PROCEDURE)/, (sql, database) => {
    const [schema, name] = quoted(sql);
    const dropped = c.routines.filter(
      (routine) =>
        routine.database === database &&
        routine.schema === schema &&
        routine.name === name
    );
    c.routines = c.routines.filter((routine) => !dropped.includes(routine));
    for (const owner of c.schemas)
      if (owner.database === database && owner.name === schema)
        owner.objects -= dropped.length;
    return [];
  });

  on(/FROM pg_namespace n WHERE n.nspowner/, (_sql, database) =>
    c.schemas
      .filter((schema) => schema.database === database)
      .map(({ name, objects }) => ({ name, objects }))
  );
  on(/^DROP SCHEMA/, (sql, database) => {
    const [name] = quoted(sql);
    const schema = c.schemas.find(
      (s) => s.database === database && s.name === name
    );
    if (schema && schema.objects > 0)
      return {
        error: `ERROR: cannot drop schema ${name} because other objects depend on it`,
      };
    c.schemas = c.schemas.filter((s) => s !== schema);
    return [];
  });

  on(/FROM svv_relation_privileges WHERE identity_name IN/, (sql, database) =>
    c.relationPrivileges
      .filter(
        (p) => p.database === database && literals(sql).includes(p.identity)
      )
      .map((p) => ({
        namespace_name: p.schema,
        relation_name: p.relation,
        identity_name: p.identity,
      }))
  );
  on(/^REVOKE ALL ON TABLE/, (sql, database) => {
    const [schema, relation, identity] = quoted(sql);
    c.relationPrivileges = c.relationPrivileges.filter(
      (p) =>
        !(
          p.byConnector &&
          p.database === database &&
          p.schema === schema &&
          p.relation === relation &&
          p.identity === identity
        )
    );
    return [];
  });
  on(/FROM svv_schema_privileges WHERE identity_name IN/, (sql, database) =>
    c.schemaPrivileges
      .filter(
        (p) => p.database === database && literals(sql).includes(p.identity)
      )
      .map((p) => ({ namespace_name: p.schema, identity_name: p.identity }))
  );
  on(/^REVOKE ALL ON SCHEMA/, (sql, database) => {
    const [schema, identity] = quoted(sql);
    c.schemaPrivileges = c.schemaPrivileges.filter(
      (p) =>
        !(
          p.byConnector &&
          p.database === database &&
          p.schema === schema &&
          p.identity === identity
        )
    );
    return [];
  });

  /** Fails the next statement that matches, once. */
  const failOnce = (match: RegExp, error = "ERROR: connection reset") => {
    let failed = false;
    on(match, () => {
      if (failed) return undefined;
      failed = true;
      return { error };
    });
  };

  return { catalog: c, failOnce };
};
