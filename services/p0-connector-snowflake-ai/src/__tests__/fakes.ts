import type { Logger } from "@p0security/connector-core";
import type * as SecretManagerClientModule from "@p0security/connector-secret-manager-client";
import type {
  SecretManagerClient,
  SecretRef,
} from "@p0security/connector-secret-manager-client";
import { generateKeyPairSync } from "node:crypto";
import { Writable } from "node:stream";
import { pino } from "pino";

import type { RequestContext } from "../context.ts";
import type { SnowflakeSession } from "../snowflake/client.ts";

export const PRIVATE_KEY_SECRET =
  "p0_install_snowflake-ai_ORG-ACCT_private-key";
export const PRIVATE_KEY = generateKeyPairSync("rsa", {
  modulusLength: 2048,
  privateKeyEncoding: { type: "pkcs8", format: "pem" },
  publicKeyEncoding: { type: "spki", format: "pem" },
}).privateKey;
export const TOKEN = "pat-secret-value-0123456789";
export const NAME = "P0_AGENT_R123";

export const install = {
  account: "ORG-ACCT",
  secrets: {
    manager: "gcp" as const,
    projectId: "proj",
    privateKeySecretId: PRIVATE_KEY_SECRET,
  },
  connector: {
    user: "P0_AI_CONNECTOR",
    role: "P0_AI_CONNECTOR",
    warehouse: "P0_AI_WH",
  },
  mcpServer: "P0_AI.MCP.P0_SQL_V1",
  agentAuthPolicy: "P0_AI.MCP.P0_AGENT_AUTH",
};

export const context: RequestContext = {
  ...install,
  requestId: "r123",
  warehouse: "ANALYTICS_WH",
  daysToExpiry: 2,
  comment: "request r123, agent a1, requestor x@example.com",
  secretName: "p0_access-token_snowflake-ai_ORG-ACCT_4f2a9c",
};

/**
 * A Snowflake session that records each statement. `respond` answers a
 * statement (rows, or a thrown error), matched by a prefix of its text.
 */
export const fakeSession = () => {
  const statements: string[] = [];
  const responses: { prefix: string; respond: () => unknown[] }[] = [];
  const answer = (sqlText: string) => {
    statements.push(sqlText);
    const match = responses.find(({ prefix }) => sqlText.startsWith(prefix));
    return match ? match.respond() : [];
  };
  const session: SnowflakeSession = {
    execute: async (sqlText) => {
      answer(sqlText);
      return `qid-${statements.length}`;
    },
    query: async <T>(sqlText: string) => answer(sqlText) as T[],
  };
  return {
    session,
    statements,
    on: (prefix: string, respond: () => unknown[]) => {
      responses.unshift({ prefix, respond });
    },
    failOn: (prefix: string, error: unknown) => {
      responses.unshift({
        prefix,
        respond: () => {
          throw error;
        },
      });
    },
  };
};

/** A pino logger that keeps every line it writes, at every level. */
export const capturingLogger = () => {
  const lines: string[] = [];
  const stream = new Writable({
    write(chunk, _encoding, done) {
      lines.push(chunk.toString());
      done();
    },
  });
  const logger: Logger = pino({ level: "trace" }, stream);
  return { logger, lines };
};

/** In-memory secrets, keyed by secret id: id → latest value. */
export const fakeSecrets = (actual: typeof SecretManagerClientModule) => {
  const values = new Map<string, string>();
  const existing = new Set<string>();
  /** Each is `false`, or the error that call throws. */
  const failures: { createSecretVersion: unknown; createSecret: unknown } = {
    createSecretVersion: false,
    createSecret: false,
  };
  const fail = (failure: unknown, fallback: string) => {
    if (failure === false) return;
    throw failure === true ? new Error(fallback) : failure;
  };
  const client = {
    getSecretValue: async ({ ref }: { ref: SecretRef }) => {
      const value = values.get(ref);
      if (value === undefined) throw new actual.SecretNotFoundError(ref);
      return { value };
    },
    createSecret: async ({ name }: { name: string }) => {
      fail(failures.createSecret, "create failed");
      if (existing.has(name)) throw new actual.SecretAlreadyExistsError(name);
      existing.add(name);
      return { ref: `projects/1/secrets/${name}`, name };
    },
    createSecretVersion: async ({
      ref,
      value,
    }: {
      ref: SecretRef;
      value: Buffer;
    }) => {
      fail(failures.createSecretVersion, "write failed");
      values.set(ref, value.toString("utf8"));
    },
    getSecret: async ({ ref }: { ref: SecretRef }) => {
      if (!existing.has(ref)) throw new actual.SecretNotFoundError(ref);
      return { ref, name: ref };
    },
    deleteSecret: async ({ ref }: { ref: SecretRef }) => {
      if (!existing.has(ref)) throw new actual.SecretNotFoundError(ref);
      existing.delete(ref);
      values.delete(ref);
    },
  };
  return {
    client: client as unknown as SecretManagerClient,
    values,
    existing,
    failures,
  };
};
