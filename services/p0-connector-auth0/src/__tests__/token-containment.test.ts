import {
  createLogger,
  newCloudFunctionLink,
  newTRPCConnectorClient,
} from "@p0security/connector";
import {
  SecretNotFoundError,
  type SecretRef,
  UnauthorizedError,
} from "@p0security/secret-manager-client";
import type * as secretManagerClient from "@p0security/secret-manager-client";
import { format, inspect } from "node:util";
import type * as pinoModule from "pino";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { rateLimitRetry } from "../auth0/api.ts";
import { connectorRouter, t } from "../router.ts";
import {
  type Auth0Call,
  type Auth0Reply,
  type FakeAuth0,
  failing,
  newFakeAuth0,
} from "./fake-auth0.ts";
import {
  ALLOWED_PATTERN,
  CLIENT_ID,
  CLIENT_SECRET,
  CREDENTIALS,
  EMAIL,
  TENANT,
} from "./fixtures.ts";

/**
 * The client secret, and the access tokens the tenant exchanges it for, never
 * leave the connector. The secret is read from the customer's vault and goes
 * to the tenant only, in the body of the token exchange only. An access token
 * goes to the tenant only, in the `Authorization` header only. Neither is
 * ever in a response P0 gets, an error, a log line, a URL or another request.
 *
 * Each call is driven through the real router twice: from P0's side, through
 * the Lambda handler, and in-process, for the error the router throws with
 * its whole cause chain.
 */

// `vi.hoisted` guarantees these exist before the (hoisted) `vi.mock` factories run.
const vault = vi.hoisted(() => ({
  createSecretManagerClient: vi.fn(),
  getSecretValue: vi.fn(),
}));
const logged = vi.hoisted((): { lines: string[] } => ({ lines: [] }));

vi.mock("@p0security/secret-manager-client", async (importOriginal) => ({
  ...(await importOriginal<typeof secretManagerClient>()),
  createSecretManagerClient: vault.createSecretManagerClient,
}));

// Every logger writes here instead of stdout, at every level, so a debug line
// can't hide a leak. The redaction is the real one.
vi.mock("pino", async (importOriginal) => {
  const actual = await importOriginal<typeof pinoModule>();
  const pino = Object.assign(
    (options: pinoModule.LoggerOptions) =>
      actual.pino(
        { ...options, level: "trace" },
        { write: (line: string) => void logged.lines.push(line) }
      ),
    actual.pino
  );
  return { ...actual, pino, default: pino };
});

for (const method of ["debug", "error", "info", "log", "warn"] as const) {
  vi.spyOn(console, method).mockImplementation((...args) => {
    logged.lines.push(format(...args));
  });
}

// The Lambda entry point reads the pattern as it loads.
vi.stubEnv("DOMAIN_ALLOW_PATTERN", ALLOWED_PATTERN);
const { handler } = await import("../index.ts");

type Operation = {
  path: string;
  /** The tRPC client's method for it. */
  type: "mutate" | "query";
  input: unknown;
  /** Whether a working call reads the secret and calls the tenant. */
  callsAuth0: boolean;
};

const operation =
  (type: Operation["type"]) =>
  (path: string, input: unknown, callsAuth0 = true): Operation => ({
    path: `auth0.${path}`,
    type,
    input,
    callsAuth0,
  });
const query = operation("query");
const mutation = operation("mutate");

const ALICE_ID = "auth0|alice";
const ROLE_CONTEXT = {
  ...CREDENTIALS,
  requestId: "req-1",
  auth0UserId: ALICE_ID,
  roleId: "rol_admin",
};

const ORG_CONTEXT = {
  ...CREDENTIALS,
  requestId: "req-2",
  auth0UserId: ALICE_ID,
  organizationId: "org_1",
  roleId: "rol_admin",
  wasMember: false,
  priorRoleIds: [],
};

const PERMISSION = {
  resourceServerIdentifier: "urn:api",
  permissionName: "do:things",
};
const PERMISSION_CONTEXT = {
  ...CREDENTIALS,
  requestId: "req-3",
  auth0UserId: ALICE_ID,
  ...PERMISSION,
};

const list = (access: string, listerQuery: Record<string, unknown>) =>
  query(`accesses.${access}.list`, {
    query: { context: CREDENTIALS, ...listerQuery },
  });

const OPERATIONS: [string, Operation][] = [
  ["install validation", query("install.validation.get", CREDENTIALS)],
  ["look up the users", list("role", { type: "users", email: EMAIL })],
  ["list the roles", list("role", { type: "roles" })],
  [
    "list the user's roles",
    list("role", { type: "user-roles", email: EMAIL, userId: ALICE_ID }),
  ],
  [
    "provisionUser",
    mutation(
      "accesses.role.provisionUser",
      { userBody: EMAIL, context: ROLE_CONTEXT },
      false
    ),
  ],
  [
    "grant a role",
    mutation("accesses.role.setPoliciesForUser", {
      userId: EMAIL,
      userBody: EMAIL,
      policies: [{ roleId: "rol_admin" }],
      context: ROLE_CONTEXT,
    }),
  ],
  [
    "list the user's membership",
    list("organization", {
      type: "org-membership",
      email: EMAIL,
      userId: ALICE_ID,
      organizationId: "org_1",
    }),
  ],
  [
    "grant a membership and a role",
    mutation("accesses.organization.setPoliciesForUser", {
      userId: EMAIL,
      userBody: EMAIL,
      policies: [{ organizationId: "org_1", roleId: "rol_admin" }],
      context: ORG_CONTEXT,
    }),
  ],
  [
    "revoke a membership and a role",
    mutation("accesses.organization.setPoliciesForUser", {
      userId: EMAIL,
      userBody: EMAIL,
      policies: [null],
      context: ORG_CONTEXT,
    }),
  ],
  [
    "list the user's permissions",
    list("permission", {
      type: "user-permissions",
      email: EMAIL,
      userId: ALICE_ID,
      resourceServerIdentifier: "https://api.acme.com",
    }),
  ],
  [
    "grant a permission",
    mutation("accesses.permission.setPoliciesForUser", {
      userId: EMAIL,
      userBody: EMAIL,
      policies: [PERMISSION],
      context: PERMISSION_CONTEXT,
    }),
  ],
  [
    "revoke a permission",
    mutation("accesses.permission.setPoliciesForUser", {
      userId: EMAIL,
      userBody: EMAIL,
      policies: [null],
      context: PERMISSION_CONTEXT,
    }),
  ],
  [
    "revoke a role",
    mutation("accesses.role.setPoliciesForUser", {
      userId: EMAIL,
      userBody: EMAIL,
      policies: [null],
      context: ROLE_CONTEXT,
    }),
  ],
];

type Answers = (call: Auth0Call) => Auth0Reply | undefined;

type Scenario = {
  /** The tenant's answer to a call, when it isn't the fake's own. */
  auth0?: Answers;
  /** What the secret holds: the client secret, unless this says otherwise. */
  stored?: Buffer | string;
  /** How reading the secret fails, if it does. */
  vaultError?: Error;
};

type Observed = {
  /** What P0 got back and what the router returned or threw, rendered every way either might be written out. */
  outputs: string[];
  /** The error P0's client got, if the call failed. */
  p0Error: unknown;
  /** Whether the call asked the vault for the secret. */
  readSecret: boolean;
  logs: string[];
  tenant: FakeAuth0;
};

/** Every way a value might be written out: inspected, as JSON, and down its cause chain. */
const renderings = (value: unknown, depth = 0): string[] => {
  if (value === undefined || depth > 10) return [];
  const asJson = (v: unknown) => {
    try {
      return JSON.stringify(v) ?? "";
    } catch {
      return "";
    }
  };
  const ownProperties =
    typeof value === "object" && value !== null
      ? Object.fromEntries(
          Object.getOwnPropertyNames(value).map((name) => [
            name,
            Reflect.get(value, name),
          ])
        )
      : value;
  return [
    inspect(value, { depth: null, showHidden: true }),
    asJson(value),
    asJson(ownProperties),
    ...(value instanceof Error
      ? [String(value.stack), ...renderings(value.cause, depth + 1)]
      : []),
  ];
};

const settle = async (
  run: () => Promise<unknown>
): Promise<{ result?: unknown; error?: unknown }> => {
  try {
    return { result: await run() };
  } catch (error) {
    return { error };
  }
};

/**
 * Calls the procedure at a dotted path on a tRPC client or caller, which are
 * proxies all the way down.
 */
const invoke = async (
  root: unknown,
  path: string,
  input: unknown
): Promise<unknown> => {
  const procedure = path.split(".").reduce<unknown>((node, key) => {
    if ((typeof node !== "object" && typeof node !== "function") || !node) {
      throw new Error(`nothing at ${key} on the way to ${path}`);
    }
    return Reflect.get(node, key);
  }, root);
  if (typeof procedure !== "function") {
    throw new Error(`${path} isn't a procedure`);
  }
  return procedure(input);
};

// P0's side of the wire: a tRPC client invoking the Lambda handler, the way
// the control plane does.
const p0 = newTRPCConnectorClient<typeof connectorRouter>({
  links: [
    newCloudFunctionLink(
      async (input) =>
        new TextEncoder().encode(
          JSON.stringify(await handler(JSON.parse(input)))
        ).buffer
    ),
  ],
});
const connector = t.createCallerFactory(connectorRouter)({
  logger: createLogger(),
});

let versions = 0;

const observe = async (
  { auth0, stored = CLIENT_SECRET, vaultError }: Scenario,
  { path, type, input }: Operation
): Promise<Observed> => {
  logged.lines.length = 0;
  vault.createSecretManagerClient.mockResolvedValue({
    getSecretValue: vault.getSecretValue,
  });
  if (vaultError) vault.getSecretValue.mockRejectedValue(vaultError);
  else {
    // A new version of the secret each time, so each observation starts
    // without a cached access token.
    vault.getSecretValue.mockResolvedValue({
      value: stored,
      version: { ref: `auth0-client-secret/versions/${++versions}` },
    });
  }

  const tenant = newFakeAuth0({
    tenant: TENANT,
    clientId: CLIENT_ID,
    clientSecret: CLIENT_SECRET,
  });
  tenant.users.push({
    user_id: ALICE_ID,
    email: EMAIL,
    connection: "Username-Password-Authentication",
    roles: [],
    permissions: [],
  });
  tenant.roles.push({ id: "rol_admin", name: "Admin", permissions: [] });
  tenant.organizations.push({ id: "org_1", name: "acme", members: new Map() });
  tenant.apis.push({
    identifier: "urn:api",
    name: "API",
    scopes: [{ value: "do:things" }],
  });
  if (auth0) tenant.intercept(auth0);
  vi.stubGlobal("fetch", tenant.fetch);

  const fromP0 = await settle(() => invoke(p0, `${path}.${type}`, input));
  const inProcess = await settle(() => invoke(connector, path, input));
  return {
    outputs: [fromP0, inProcess].flatMap(({ result, error }) =>
      renderings(error ?? result)
    ),
    p0Error: fromP0.error,
    readSecret: vault.getSecretValue.mock.calls.length > 0,
    logs: [...logged.lines],
    tenant,
  };
};

type Secret = { name: string; value: string };

const secretsOf = (stored: string, tokens: string[]): Secret[] => [
  { name: "the client secret", value: CLIENT_SECRET },
  { name: "the stored secret", value: stored },
  ...tokens.flatMap((token) => {
    const [, payload = token, signature = token] = token.split(".");
    return [
      { name: "an access token", value: token },
      { name: "an access token's payload", value: payload },
      { name: "an access token's signature", value: signature },
    ];
  }),
];

/** One line per text that holds a secret, naming what it holds. */
const leaks = (texts: string[], secrets: Secret[]) =>
  texts.flatMap((text) => {
    const found = new Set(
      secrets
        .filter(({ value }) => value !== "" && text.includes(value))
        .map(({ name }) => name)
    );
    return found.size > 0
      ? [`${[...found].join("; ")}, in: ${text.slice(0, 200)}`]
      : [];
  });

const TOKEN_EXCHANGE = "/oauth/token";

const expectSecretContained = (
  { outputs, logs, tenant }: Observed,
  stored: string = CLIENT_SECRET
) => {
  const secrets = secretsOf(stored.trim(), tenant.tokens);

  expect(leaks(outputs, secrets)).toEqual([]);
  expect(leaks(logs, secrets)).toEqual([]);
  // Whatever credential an Authorization header carried, it's never repeated.
  expect([...outputs, ...logs].filter((text) => /bearer/i.test(text))).toEqual(
    []
  );

  for (const { url, path, headers, rawBody, redirect } of tenant.calls) {
    expect(url.startsWith(`https://${TENANT}/`)).toBe(true);
    // Nothing is resent to wherever a redirect points.
    expect(redirect).toBe("error");
    const { authorization, ...otherHeaders } = headers;
    if (path === TOKEN_EXCHANGE) {
      // The one request that carries the secret: in its body, with no token.
      expect(authorization).toBeUndefined();
      expect(rawBody).toBe(
        JSON.stringify({
          grant_type: "client_credentials",
          client_id: CLIENT_ID,
          client_secret: stored.trim(),
          audience: `https://${TENANT}/api/v2/`,
        })
      );
      expect(leaks([url, JSON.stringify(otherHeaders)], secrets)).toEqual([]);
    } else {
      // Every other request carries a token the tenant issued, in its
      // Authorization header and nowhere else, and never the secret.
      expect(tenant.tokens.map((token) => `Bearer ${token}`)).toContain(
        authorization
      );
      expect(
        leaks([url, JSON.stringify(otherHeaders), rawBody ?? ""], secrets)
      ).toEqual([]);
    }
  }
};

/** {@link observe}, for a call that gets as far as the secret, then checks it went no further. */
const sweep = async (scenario: Scenario, operation: Operation) => {
  const observed = await observe(scenario, operation);
  // A call that never reads the secret proves nothing about it.
  expect(observed.readSecret).toBe(operation.callsAuth0);
  expectSecretContained(observed, scenario.stored?.toString("utf8"));
  return observed;
};

beforeEach(() => {
  // A 429 is retried after a wait. These tests only care how it ends.
  rateLimitRetry.waitMs = 0;
  vi.clearAllMocks();
});

// The second call of a run sends the token the first one cached. Refusing it
// once makes the connector drop it, exchange again and retry.
const refusingTheSecondToken = (): Answers => {
  let carryingToken = 0;
  return (call) => {
    if (call.path === TOKEN_EXCHANGE) return undefined;
    carryingToken += 1;
    return carryingToken === 2 ? failing(401, "Invalid token") : undefined;
  };
};

describe("a 401 for the token it accepted a moment ago", () => {
  it.each(OPERATIONS)("%s", async (_name, operation) => {
    await sweep({ auth0: refusingTheSecondToken() }, operation);
  });
});

describe("a working install", () => {
  it.each(OPERATIONS)(
    "%s succeeds, and the secret stays in the connector",
    async (_name, operation) => {
      const observed = await sweep({}, operation);

      expect(observed.p0Error).toBeUndefined();
      // Otherwise no credential was in play, and this proves nothing.
      expect(observed.tenant.exchanges().length > 0).toBe(operation.callsAuth0);
      // Nor if the connector's log lines weren't the ones checked.
      expect(observed.logs).not.toEqual([]);
    }
  );
});

// The tenant quoting the request back: its body, and its Authorization header.
const quoting =
  (status: number) =>
  (call: Auth0Call): Auth0Reply => ({
    status,
    body: {
      statusCode: status,
      error: `rejected ${call.rawBody ?? ""}`,
      message: `rejected ${call.rawBody ?? ""} sent with ${call.headers.authorization ?? "no credential"}`,
      error_description: call.headers.authorization?.replace(/^Bearer /, ""),
      errorCode: call.headers.authorization,
    },
  });

const AUTH0_FAILURES: [string, (call: Auth0Call) => Auth0Reply][] = [
  ["400", () => failing(400, "Payload validation error", "invalid_body")],
  ["400, quoting the request back", quoting(400)],
  ["401", () => failing(401, "Invalid token", "invalid_token")],
  ["401, quoting the request back", quoting(401)],
  ["403", () => failing(403, "Insufficient scope", "insufficient_scope")],
  ["403, quoting the request back", quoting(403)],
  ["404", () => failing(404)],
  ["409", () => failing(409, "conflict")],
  ["409, quoting the request back", quoting(409)],
  [
    "429",
    () =>
      failing(429, "Too Many Requests", "too_many_requests", {
        "x-ratelimit-reset": "1",
      }),
  ],
  ["500", () => ({ status: 500, body: "" })],
  ["500, quoting the request back", quoting(500)],
  [
    "502 with an HTML page",
    () => ({ status: 502, body: "<html>Bad Gateway</html>" }),
  ],
  [
    "a 200 the connector can't read",
    (call) => ({
      status: 200,
      body: { unexpected: call.headers.authorization, echoed: call.body },
    }),
  ],
  [
    "nothing, the network failing",
    () => ({
      throws: new TypeError("fetch failed", {
        cause: Object.assign(new Error("connect ECONNREFUSED 1.2.3.4:443"), {
          code: "ECONNREFUSED",
        }),
      }),
    }),
  ],
  [
    "nothing in time",
    () => ({
      throws: new DOMException(
        "The operation was aborted due to timeout",
        "TimeoutError"
      ),
    }),
  ],
  // What `fetch` throws for a header value it won't send.
  [
    "nothing, fetch quoting the request's Authorization header",
    (call) => ({
      throws: new TypeError(
        `Headers.append: "${call.headers.authorization ?? "no credential"}" is an invalid header value.`
      ),
    }),
  ],
  // What `fetch` might throw quoting the body it was sending.
  [
    "nothing, fetch quoting the request's body",
    (call) => ({ throws: new TypeError(`could not send ${call.rawBody}`) }),
  ],
];

const TARGETS: [string, (call: Auth0Call) => boolean][] = [
  ["the token exchange", ({ path }) => path === TOKEN_EXCHANGE],
  [
    "every call that carries an access token",
    ({ path }) => path !== TOKEN_EXCHANGE,
  ],
];

describe.each(
  TARGETS.flatMap(([target, matches]) =>
    AUTH0_FAILURES.map(
      ([answer, reply]) => [answer, target, matches, reply] as const
    )
  )
)("Auth0 answering %s to %s", (_answer, _target, matches, reply) => {
  it.each(OPERATIONS)("%s", async (_name, operation) => {
    await sweep(
      { auth0: (call) => (matches(call) ? reply(call) : undefined) },
      operation
    );
  });
});

const awsError = (name: string, message: string) =>
  Object.assign(new Error(message), {
    name,
    $metadata: { httpStatusCode: 400, requestId: "aws-req-1" },
  });

const VAULT_FAILURES: [string, Error][] = [
  [
    "can't find the secret",
    new SecretNotFoundError("auth0-client-secret" as SecretRef, {
      cause: awsError(
        "ResourceNotFoundException",
        "Secrets Manager can't find the specified secret."
      ),
    }),
  ],
  [
    "won't let the connector read it",
    new UnauthorizedError("aws", {
      cause: awsError(
        "AccessDeniedException",
        "User: arn:aws:sts::123456789012:assumed-role/p0-connector/fn is not authorized to perform: secretsmanager:GetSecretValue"
      ),
    }),
  ],
  [
    "fails some other way",
    awsError("InternalServiceError", "An error occurred on the server side."),
  ],
];

describe.each(VAULT_FAILURES)("a vault that %s", (_case, vaultError) => {
  it.each(OPERATIONS)("%s", async (_name, operation) => {
    const observed = await sweep({ vaultError }, operation);

    // Without the secret there's nothing to call the tenant with.
    expect(observed.tenant.calls).toEqual([]);
  });
});

const STORED_SECRETS: [string, Buffer | string][] = [
  ["holds the secret with a trailing newline", `${CLIENT_SECRET}\n`],
  ["holds the secret as a binary secret", Buffer.from(CLIENT_SECRET, "utf8")],
  // What the AWS console's key/value editor stores. The tenant refuses it.
  [
    "holds the secret as a JSON key/value pair",
    JSON.stringify({ client_secret: CLIENT_SECRET }),
  ],
  ["holds another client's secret", "auth0_secret_SENTINELother9c1f"],
];

describe.each(STORED_SECRETS)("a secret that %s", (_case, stored) => {
  it.each(OPERATIONS)("%s", async (_name, operation) => {
    await sweep({ stored }, operation);
  });
});

describe("an empty secret", () => {
  it.each(OPERATIONS)("%s", async (_name, operation) => {
    const observed = await sweep({ stored: " \n" }, operation);

    // There's no secret to exchange.
    expect(observed.tenant.calls).toEqual([]);
  });
});

describe("the secret where the pointer goes", () => {
  it("is refused as the pointer, without being repeated", async () => {
    const observed = await observe(
      {},
      query("install.validation.get", {
        ...CREDENTIALS,
        clientSecret: CLIENT_SECRET,
      })
    );

    expect(observed.p0Error).toMatchObject({ data: { code: "BAD_REQUEST" } });
    expect(vault.getSecretValue).not.toHaveBeenCalled();
    expectSecretContained(observed);
  });
});
