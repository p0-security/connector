import {
  createLogger,
  newCloudFunctionLink,
  newTRPCConnectorClient,
} from "@p0security/connector-core";
import {
  SecretNotFoundError,
  type SecretRef,
  UnauthorizedError,
} from "@p0security/secret-manager-client";
import type * as secretManagerClient from "@p0security/secret-manager-client";
import { format, inspect } from "node:util";
import type * as pinoModule from "pino";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { connectorRouter, t } from "../router.ts";
import {
  type FakeDockerHub,
  type HubCall,
  type HubReply,
  failing,
  newFakeDockerHub,
} from "./fake-docker-hub.ts";
import {
  ALLOWED_PATTERN,
  CREDENTIALS,
  EMAIL,
  TOKEN,
  UUID,
} from "./fixtures.ts";

/**
 * The organization access token, and the JWTs Docker Hub exchanges it for,
 * never leave the connector. The token is read from the customer's vault and
 * goes to hub.docker.com only, in the body of the token exchange only. A JWT
 * goes to hub.docker.com only, in the `Authorization` header only. Neither is
 * ever in a response P0 gets, an error, a log line, a URL or another request.
 *
 * Each call is driven through the real router twice: from P0's side, through
 * the Lambda handler, and in-process, for the error the router throws with its
 * whole cause chain. The second run meets the JWT the first one cached.
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

/**
 * Alice was in the org when she asked. Bob wasn't, so P0 invites him. Carol's
 * invite is still pending, and Dave accepted his.
 */
const ALICE = { username: "alice", uuid: UUID, email: EMAIL, role: "editor" };
const BOB_EMAIL = "bob@acme.com";
const CAROL_EMAIL = "carol@acme.com";
const DAVE = {
  username: "dave",
  uuid: "dave-uuid",
  email: "dave@acme.com",
  role: "editor",
};

const INVITED = {
  ...CREDENTIALS,
  requestId: "req-1",
  standingMember: null,
  grantCompleted: true,
};
const STANDING = {
  ...INVITED,
  requestId: "req-2",
  standingMember: {
    username: ALICE.username,
    uuid: ALICE.uuid,
    priorRole: "member" as const,
  },
};

type Operation = {
  path: string;
  /** The tRPC client's method for it. */
  type: "mutate" | "query";
  input: unknown;
  /** Whether a working call reads the token and calls Docker Hub. */
  callsDockerHub: boolean;
};

const operation =
  (type: Operation["type"]) =>
  (path: string, input: unknown, callsDockerHub = true): Operation => ({
    path: `docker.${path}`,
    type,
    input,
    callsDockerHub,
  });
const query = operation("query");
const mutation = operation("mutate");

const list = (type: "invite" | "member", email: string) =>
  query("accesses.role.list", {
    query: { type, context: CREDENTIALS, email },
  });

const setRole = ({
  context,
  email,
  role,
}: {
  context: typeof INVITED | typeof STANDING;
  email: string;
  role: "owner" | null;
}) =>
  mutation("accesses.role.setPoliciesForUser", {
    userId: email,
    userBody: email,
    policies: [{ role }],
    context,
  });

// The router has no `stage`: P0 stages a grant through provisionUser and
// identifyUser, and every grant and revoke is a setPoliciesForUser.
const OPERATIONS: [string, Operation][] = [
  ["install validation", query("install.validation.get", CREDENTIALS)],
  ["look up a member", list("member", ALICE.email)],
  ["look up an invite", list("invite", CAROL_EMAIL)],
  [
    "provisionUser",
    mutation(
      "accesses.role.provisionUser",
      { userBody: ALICE.email, context: STANDING },
      false
    ),
  ],
  [
    "identifyUser",
    mutation(
      "accesses.role.identifyUser",
      { userBody: BOB_EMAIL, context: INVITED },
      false
    ),
  ],
  [
    "grant to a standing member",
    setRole({ context: STANDING, email: ALICE.email, role: "owner" }),
  ],
  [
    "grant by invite",
    setRole({ context: INVITED, email: BOB_EMAIL, role: "owner" }),
  ],
  [
    "revoke to the prior role",
    setRole({ context: STANDING, email: ALICE.email, role: null }),
  ],
  [
    "revoke an invite",
    setRole({ context: INVITED, email: CAROL_EMAIL, role: null }),
  ],
  [
    "revoke a membership",
    setRole({ context: INVITED, email: DAVE.email, role: null }),
  ],
  [
    "deleteUser",
    mutation(
      "accesses.role.deleteUser",
      { userId: ALICE.email, userBody: ALICE.email, context: STANDING },
      false
    ),
  ],
];

type Answers = (call: HubCall) => HubReply | undefined;

type Scenario = {
  /** Docker Hub's answer to a call, when it isn't the fake's own. */
  docker?: Answers;
  /** What the secret holds: the token, unless this says otherwise. */
  stored?: Buffer | string;
  /** How reading the secret fails, if it does. */
  vaultError?: Error;
};

type Observed = {
  /** What P0 got back and what the router returned or threw, rendered every way either might be written out. */
  outputs: string[];
  /** The error P0's client got, if the call failed. */
  p0Error: unknown;
  /** Whether the call asked the vault for the token. */
  readToken: boolean;
  logs: string[];
  hub: FakeDockerHub;
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
  { docker, stored = TOKEN, vaultError }: Scenario,
  { path, type, input }: Operation
): Promise<Observed> => {
  logged.lines.length = 0;
  vault.createSecretManagerClient.mockResolvedValue({
    getSecretValue: vault.getSecretValue,
  });
  if (vaultError) vault.getSecretValue.mockRejectedValue(vaultError);
  else {
    // A new version of the secret each time, so each observation starts
    // without a cached JWT.
    vault.getSecretValue.mockResolvedValue({
      value: stored,
      version: { ref: `docker-oat/versions/${++versions}` },
    });
  }

  const hub = newFakeDockerHub({ org: "acme", token: TOKEN });
  hub.members.push({ ...ALICE }, { ...DAVE });
  hub.invites.push({ id: "invite-7", invitee: CAROL_EMAIL, role: "editor" });
  if (docker) hub.intercept(docker);
  vi.stubGlobal("fetch", hub.fetch);

  const fromP0 = await settle(() => invoke(p0, `${path}.${type}`, input));
  const inProcess = await settle(() => invoke(connector, path, input));
  return {
    outputs: [fromP0, inProcess].flatMap(({ result, error }) =>
      renderings(error ?? result)
    ),
    p0Error: fromP0.error,
    readToken: vault.getSecretValue.mock.calls.length > 0,
    logs: [...logged.lines],
    hub,
  };
};

type Secret = { name: string; value: string };

const secretsOf = (stored: string, jwts: string[]): Secret[] => [
  { name: "the token", value: TOKEN },
  { name: "the token's body", value: TOKEN.slice("dckr_oat_".length) },
  { name: "the stored secret", value: stored },
  ...jwts.flatMap((jwt) => {
    const [, payload = jwt, signature = jwt] = jwt.split(".");
    return [
      { name: "a JWT", value: jwt },
      { name: "a JWT's payload", value: payload },
      { name: "a JWT's signature", value: signature },
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

const TOKEN_EXCHANGE = "/v2/auth/token";

const expectTokenContained = (
  { outputs, logs, hub }: Observed,
  stored: string = TOKEN
) => {
  const secrets = secretsOf(stored.trim(), hub.jwts);

  expect(leaks(outputs, secrets)).toEqual([]);
  expect(leaks(logs, secrets)).toEqual([]);
  // Whatever credential an Authorization header carried, it's never repeated.
  expect([...outputs, ...logs].filter((text) => /bearer/i.test(text))).toEqual(
    []
  );

  for (const { url, path, headers, rawBody, redirect } of hub.calls) {
    expect(url.startsWith("https://hub.docker.com/v2/")).toBe(true);
    const { authorization, ...otherHeaders } = headers;
    if (path === TOKEN_EXCHANGE) {
      // The one request that carries the token: in its body, with no JWT, and
      // never resent to wherever a redirect points.
      expect(authorization).toBeUndefined();
      expect(rawBody).toBe(
        JSON.stringify({ identifier: "acme", secret: stored.trim() })
      );
      expect(redirect).toBe("error");
      expect(leaks([url, JSON.stringify(otherHeaders)], secrets)).toEqual([]);
    } else {
      // Every other request carries a JWT Docker Hub issued, in its
      // Authorization header and nowhere else, and never the token.
      expect(hub.jwts.map((jwt) => `Bearer ${jwt}`)).toContain(authorization);
      expect(
        leaks([url, JSON.stringify(otherHeaders), rawBody ?? ""], secrets)
      ).toEqual([]);
    }
  }
};

/** {@link observe}, for a call that gets as far as the token, then checks it went no further. */
const sweep = async (scenario: Scenario, operation: Operation) => {
  const observed = await observe(scenario, operation);
  // A call that never reads the token proves nothing about it.
  expect(observed.readToken).toBe(operation.callsDockerHub);
  expectTokenContained(observed, scenario.stored?.toString("utf8"));
  return observed;
};

beforeEach(() => {
  vi.clearAllMocks();
});

describe("a working install", () => {
  it.each(OPERATIONS)(
    "%s succeeds, and the token stays in the connector",
    async (_name, operation) => {
      const observed = await sweep({}, operation);

      expect(observed.p0Error).toBeUndefined();
      // Otherwise no credential was in play, and this proves nothing.
      expect(observed.hub.exchanges().length > 0).toBe(
        operation.callsDockerHub
      );
      expect(observed.hub.apiCalls().length > 0).toBe(operation.callsDockerHub);
      // Nor if the connector's log lines weren't the ones checked.
      expect(observed.logs).not.toEqual([]);
    }
  );

  // The in-process run comes second, and meets the JWT the first one cached.
  it("reuses the first run's JWT for the second", async () => {
    const { hub } = await observe({}, list("member", ALICE.email));

    expect(hub.exchanges()).toHaveLength(1);
    expect(hub.apiCalls()).toHaveLength(2);
  });

  // Each line carries what the request's logger was given.
  it("logs each Docker Hub request under the request's id and org", async () => {
    const { logs } = await observe(
      {},
      setRole({ context: INVITED, email: BOB_EMAIL, role: "owner" })
    );

    const requests = logs.filter((line) => line.includes("Docker Hub request"));
    expect(requests).not.toEqual([]);
    for (const line of requests) {
      expect(JSON.parse(line)).toMatchObject({
        requestId: "req-1",
        org: "acme",
      });
    }
  });
});

// Docker Hub quoting the request back: its body, and its Authorization header.
const quoting =
  (status: number) =>
  (call: HubCall): HubReply => ({
    status,
    body: {
      message: `rejected ${call.rawBody ?? ""} sent with ${call.headers.authorization ?? "no credential"}`,
      detail: call.headers.authorization?.replace(/^Bearer /, ""),
      errinfo: { body: call.body, authorization: call.headers.authorization },
    },
  });

const DOCKER_FAILURES: [string, (call: HubCall) => HubReply][] = [
  ["400", () => failing(400, "bad request")],
  ["400, quoting the request back", quoting(400)],
  ["401", () => failing(401, "unauthorized")],
  ["401, quoting the request back", quoting(401)],
  ["403", () => ({ status: 403, body: { detail: "permission denied" } })],
  ["404", () => failing(404, "not found")],
  ["409", () => failing(409, "conflict")],
  ["409, quoting the request back", quoting(409)],
  ["429", () => failing(429, "too many requests", { "Retry-After": "30" })],
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
        cause: Object.assign(
          new Error("connect ECONNREFUSED 3.224.227.198:443"),
          { code: "ECONNREFUSED" }
        ),
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
];

const TARGETS: [string, (call: HubCall) => boolean][] = [
  ["the token exchange", ({ path }) => path === TOKEN_EXCHANGE],
  ["every call that carries a JWT", ({ path }) => path !== TOKEN_EXCHANGE],
];

describe.each(
  TARGETS.flatMap(([target, matches]) =>
    DOCKER_FAILURES.map(
      ([answer, reply]) => [answer, target, matches, reply] as const
    )
  )
)("Docker Hub answering %s to %s", (_answer, _target, matches, reply) => {
  it.each(OPERATIONS)("%s", async (_name, operation) => {
    await sweep(
      { docker: (call) => (matches(call) ? reply(call) : undefined) },
      operation
    );
  });
});

// The second call of a run sends the JWT the first one cached. Refusing it
// once makes the connector drop it, exchange the token again and retry.
const refusingTheSecondJwt = (): Answers => {
  let carryingJwt = 0;
  return (call) => {
    if (call.path === TOKEN_EXCHANGE) return undefined;
    carryingJwt += 1;
    return carryingJwt === 2 ? failing(401, "unauthorized") : undefined;
  };
};

// Each builds its answers afresh, for the ones that count calls.
const DOCKER_ANSWERS: [string, () => Answers][] = [
  [
    "a refused invite status",
    () => (call) =>
      call.path === "/v2/invites/bulk"
        ? {
            status: 202,
            body: {
              invitees: [{ invitee: BOB_EMAIL, status: "seat_limit_reached" }],
            },
          }
        : undefined,
  ],
  [
    "nobody in the org and no invites",
    () => (call) => {
      if (call.method !== "GET") return undefined;
      if (call.path === "/v2/orgs/acme/members") {
        return { status: 200, body: { next: null, results: [] } };
      }
      return call.path === "/v2/orgs/acme/invites"
        ? { status: 200, body: { data: [] } }
        : undefined;
    },
  ],
  ["a 401 for the JWT it accepted a moment ago", refusingTheSecondJwt],
];

describe.each(DOCKER_ANSWERS)(
  "Docker Hub answering with %s",
  (_answer, answers) => {
    it.each(OPERATIONS)("%s", async (_name, operation) => {
      await sweep({ docker: answers() }, operation);
    });
  }
);

describe("a 401 for a cached JWT", () => {
  // Otherwise the sweep above proves nothing about the retry.
  it("is retried with a second JWT, and neither is repeated", async () => {
    const observed = await sweep(
      { docker: refusingTheSecondJwt() },
      setRole({ context: INVITED, email: BOB_EMAIL, role: "owner" })
    );

    expect(observed.p0Error).toBeUndefined();
    expect(observed.hub.jwts).toHaveLength(2);
    expect(observed.hub.invites.map(({ invitee }) => invitee)).toContain(
      BOB_EMAIL
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
    new SecretNotFoundError("docker-oat" as SecretRef, {
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

    // Without the token there's nothing to call Docker Hub with.
    expect(observed.hub.calls).toEqual([]);
  });
});

const STORED_SECRETS: [string, Buffer | string][] = [
  ["holds the token with a trailing newline", `${TOKEN}\n`],
  ["holds the token as a binary secret", Buffer.from(TOKEN, "utf8")],
  // What the AWS console's key/value editor stores. Docker Hub refuses it.
  [
    "holds the token as a JSON key/value pair",
    JSON.stringify({ token: TOKEN }),
  ],
  ["holds another org's token", "dckr_oat_SENTINELnotacmes7f3a9c"],
];

describe.each(STORED_SECRETS)("a secret that %s", (_case, stored) => {
  it.each(OPERATIONS)("%s", async (_name, operation) => {
    await sweep({ stored }, operation);
  });
});

describe("an empty secret", () => {
  it.each(OPERATIONS)("%s", async (_name, operation) => {
    const observed = await sweep({ stored: " \n" }, operation);

    // There's no token to exchange.
    expect(observed.hub.calls).toEqual([]);
  });
});

describe("the token where the pointer goes", () => {
  it("is refused as the pointer, without being repeated", async () => {
    const observed = await observe(
      {},
      query("accesses.role.list", {
        query: {
          type: "member",
          context: { ...CREDENTIALS, tokenSecret: TOKEN },
          email: ALICE.email,
        },
      })
    );

    expect(observed.p0Error).toMatchObject({ data: { code: "BAD_REQUEST" } });
    expect(vault.getSecretValue).not.toHaveBeenCalled();
    expectTokenContained(observed);
  });
});
