import {
  createLogger,
  newCloudFunctionLink,
  newTRPCConnectorClient,
} from "@p0security/connector-core";
import {
  SecretNotFoundError,
  type SecretRef,
  UnauthorizedError,
} from "@p0security/connector-secret-manager-client";
import type * as secretManagerClient from "@p0security/connector-secret-manager-client";
import { format, inspect } from "node:util";
import type * as pinoModule from "pino";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { forgetKeyUuids } from "../cloud/client.ts";
import { connectorRouter, t } from "../router.ts";
import {
  type CloudCall,
  type CloudReply,
  type FakeCloud,
  failing,
  newSeededCloud,
  provisionP0Endpoints,
} from "./fake-cloud.ts";
import {
  ALLOWED_PATTERN,
  CREDENTIALS,
  EMAIL,
  KEY_ID,
  KEY_SECRET,
  SERVICE_ID,
  STORED_KEY,
} from "./fixtures.ts";
import { CONTEXT, MEMBER, ROLE_NAME, systemRoles } from "./setup.ts";

/**
 * The API key's secret never leaves the connector. It is read from the
 * customer's vault and goes to ClickHouse Cloud only, inside the Basic
 * `Authorization` header only, to `api.clickhouse.cloud` and
 * `queries.clickhouse.cloud` only. Neither it, nor the base64 credentials
 * that carry it, is ever in a response P0 gets, an error, a log line, a URL,
 * a body or another header.
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

vi.mock(
  "@p0security/connector-secret-manager-client",
  async (importOriginal) => ({
    ...(await importOriginal<typeof secretManagerClient>()),
    createSecretManagerClient: vault.createSecretManagerClient,
  })
);

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
  /** The hosts a working call reaches: both, unless this says otherwise. */
  hosts?: readonly string[];
  /**
   * Whether the fake starts with what the lookups and the role primitives
   * read. Not for the install, which reads none of it, nor for a lookup on a
   * service P0 hasn't set up yet, whose endpoint writes are what some
   * scenarios fail.
   */
  seeded?: false;
};

const HOSTS = ["api.clickhouse.cloud", "queries.clickhouse.cloud"];

const CLOUD_ONLY = ["api.clickhouse.cloud"];

const inService = { context: CREDENTIALS, serviceId: SERVICE_ID };

/** A lister query, through an access's `list`. */
const lister = (
  access: string,
  query: Record<string, unknown>,
  hosts: readonly string[]
): Operation => ({
  path: `clickhouse.accesses.${access}.list`,
  type: "query",
  input: { query },
  hosts,
});

/** A role the seeded fake doesn't hold yet, for `createAccessResource` to make. */
const NEW_ROLE_NAME = "p0_9f3a_alice_calm_heron";

const POLICIES = {
  sql: {
    type: "sql",
    level: "read",
    object: { database: "analytics", table: "v_users" },
  },
  // The one that reads a system role at grant time.
  console: { type: "console", consoleRole: "service-admin" },
};

/** Every route of an access that reads the key, but `list`. */
const primitiveOperations = (
  access: keyof typeof POLICIES
): [string, Operation][] => {
  const policies = [POLICIES[access]];
  const route = (name: string, input: object): [string, Operation] => [
    `${access} ${name}`,
    {
      path: `clickhouse.accesses.${access}.${name}`,
      type: "mutate",
      input: { ...input, context: CONTEXT },
      hosts: CLOUD_ONLY,
    },
  ];
  return [
    route("createAccessResource", { resourceBody: NEW_ROLE_NAME }),
    route("addPoliciesToResource", { resourceId: ROLE_NAME, policies }),
    route("bindAccessResource", {
      userId: EMAIL,
      userBody: EMAIL,
      resourceId: ROLE_NAME,
    }),
    route("unbindAccessResource", {
      userId: EMAIL,
      userBody: EMAIL,
      resourceId: ROLE_NAME,
    }),
    route("removePoliciesFromResource", { resourceId: ROLE_NAME, policies }),
    route("deleteAccessResource", { resourceId: ROLE_NAME }),
  ];
};

const OPERATIONS: [string, Operation][] = [
  [
    "install validation",
    {
      path: "clickhouse.install.validation.get",
      type: "query",
      input: CREDENTIALS,
      hosts: CLOUD_ONLY,
      seeded: false,
    },
  ],
  [
    "member lookup",
    lister(
      "sql",
      { type: "member", context: CREDENTIALS, email: EMAIL },
      CLOUD_ONLY
    ),
  ],
  [
    "services listing",
    lister("sql", { type: "services", context: CREDENTIALS }, CLOUD_ONLY),
  ],
  [
    "service lookup",
    lister("sql", { type: "service", ...inService }, CLOUD_ONLY),
  ],
  ["objects listing", lister("sql", { type: "objects", ...inService }, HOSTS)],
  [
    "objects listing on a service P0 hasn't set up",
    {
      ...lister("sql", { type: "objects", ...inService }, HOSTS),
      seeded: false,
    },
  ],
  // Every access's `list` is the same one.
  [
    "console objects listing",
    lister("console", { type: "objects", ...inService }, HOSTS),
  ],
  [
    "console service lookup",
    lister("console", { type: "service", ...inService }, CLOUD_ONLY),
  ],
  ...primitiveOperations("sql"),
  ...primitiveOperations("console"),
];

/**
 * What the lister queries and the role primitives read: a member, P0's
 * endpoints, the system roles and the request's role.
 */
const seed = (cloud: FakeCloud) => {
  cloud.members.push(MEMBER);
  cloud.roles.push(...systemRoles(), {
    id: "2c3d4e5f-6a7b-4c8d-9e0f-0a1b2c3d4e5f",
    name: ROLE_NAME,
    type: "custom",
    // Neither the bind's actors nor the base policies, so every role
    // primitive writes.
    actors: ["user/a-previous-member"],
    policies: [
      {
        allowDeny: "ALLOW",
        permissions: ["control-plane:service:view"],
        resources: [`instance/${SERVICE_ID}`],
      },
    ],
  });
  provisionP0Endpoints(cloud);
  cloud.rows.set("p0_objects", [
    { database: "analytics", name: "", kind: "database" },
  ]);
};

type Answers = (call: CloudCall) => CloudReply | undefined;

type Scenario = {
  /** ClickHouse Cloud's answer to a call, when it isn't the fake's own. */
  cloud?: Answers;
  /** What the secret holds: the key's JSON, unless this says otherwise. */
  stored?: Buffer | string;
  /** How reading the secret fails, if it does. */
  vaultError?: Error;
  /** Changes to the fake before the call. */
  setup?: (cloud: FakeCloud) => void;
};

type Observed = {
  /** What P0 got back and what the router returned or threw, rendered every way either might be written out. */
  outputs: string[];
  /** The error P0's client got, if the call failed. */
  p0Error: unknown;
  /** Whether the call asked the vault for the secret. */
  readSecret: boolean;
  logs: string[];
  cloud: FakeCloud;
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

const observe = async (
  { cloud: answers, stored = STORED_KEY, vaultError, setup }: Scenario,
  operation: Operation
): Promise<Observed> => {
  logged.lines.length = 0;
  vault.createSecretManagerClient.mockResolvedValue({
    getSecretValue: vault.getSecretValue,
  });
  if (vaultError) vault.getSecretValue.mockRejectedValue(vaultError);
  else {
    vault.getSecretValue.mockResolvedValue({
      value: stored,
      version: { ref: "clickhouse-api-key/versions/1" },
    });
  }

  // Each call finds the key's UUID afresh, so the keys listing is in play.
  forgetKeyUuids();
  const cloud = newSeededCloud();
  if (operation.seeded !== false) seed(cloud);
  setup?.(cloud);
  if (answers) cloud.intercept(answers);
  vi.stubGlobal("fetch", cloud.fetch);

  const fromP0 = await settle(() =>
    invoke(p0, `${operation.path}.${operation.type}`, operation.input)
  );
  const inProcess = await settle(() =>
    invoke(connector, operation.path, operation.input)
  );
  return {
    outputs: [fromP0, inProcess].flatMap(({ result, error }) =>
      renderings(error ?? result)
    ),
    p0Error: fromP0.error,
    readSecret: vault.getSecretValue.mock.calls.length > 0,
    logs: [...logged.lines],
    cloud,
  };
};

type Secret = { name: string; value: string };

const base64 = (text: string) => Buffer.from(text, "utf8").toString("base64");

/** The key secrets in play, and every form of each a request carries. */
const secretsOf = (stored: string): Secret[] => {
  const keySecrets = new Set([KEY_SECRET]);
  try {
    const parsed: unknown = JSON.parse(stored);
    if (
      typeof parsed === "object" &&
      parsed !== null &&
      "keySecret" in parsed &&
      typeof parsed.keySecret === "string" &&
      parsed.keySecret.trim() !== ""
    ) {
      keySecrets.add(parsed.keySecret);
    }
  } catch {
    if (stored.trim() !== "") keySecrets.add(stored.trim());
  }
  return [...keySecrets].flatMap((secret) => [
    { name: "a key secret", value: secret },
    { name: "Basic credentials", value: base64(`${KEY_ID}:${secret}`) },
  ]);
};

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

const expectSecretContained = (
  { outputs, logs, cloud }: Observed,
  stored: string = STORED_KEY
) => {
  const secrets = secretsOf(stored);

  expect(leaks(outputs, secrets)).toEqual([]);
  expect(leaks(logs, secrets)).toEqual([]);
  // Whatever credential an Authorization header carried, it's never repeated.
  expect(
    [...outputs, ...logs].filter((text) =>
      /Basic [A-Za-z0-9+/=]{8,}/.test(text)
    )
  ).toEqual([]);

  for (const { url, host, headers, rawBody, redirect } of cloud.calls) {
    expect(HOSTS).toContain(host);
    expect(url.startsWith(`https://${host}/`)).toBe(true);
    // Nothing is resent to wherever a redirect points.
    expect(redirect).toBe("error");
    const { authorization, ...otherHeaders } = headers;
    // The key travels in the Authorization header, and nowhere else.
    expect(secrets.map(({ value }) => `Basic ${value}`)).toContain(
      authorization
    );
    expect(
      leaks([url, JSON.stringify(otherHeaders), rawBody ?? ""], secrets)
    ).toEqual([]);
  }
};

/** {@link observe}, for a call that gets as far as the secret, then checks it went no further. */
const sweep = async (scenario: Scenario, operation: Operation) => {
  const observed = await observe(scenario, operation);
  // A call that never reads the secret proves nothing about it.
  expect(observed.readSecret).toBe(true);
  expectSecretContained(observed, scenario.stored?.toString("utf8"));
  return observed;
};

beforeEach(() => {
  vi.clearAllMocks();
});

describe("a working install", () => {
  it.each(OPERATIONS)(
    "%s succeeds, and the key stays in the connector",
    async (_name, operation) => {
      const observed = await sweep({}, operation);

      expect(observed.p0Error).toBeUndefined();
      // Otherwise the key wasn't in play on each host, and this proves nothing.
      expect(new Set(observed.cloud.calls.map(({ host }) => host))).toEqual(
        new Set(operation.hosts ?? HOSTS)
      );
      // Nor if the connector's log lines weren't the ones checked.
      expect(observed.logs).not.toEqual([]);
      // Each role primitive writes, so failing the writes reaches it.
      if (operation.type === "mutate") {
        expect(observed.cloud.writes()).not.toEqual([]);
      }
    }
  );
});

// The user is the requestor's email, so these never need the key.
describe.each(["sql", "console"])("the %s access's user routes", (access) => {
  it.each(["provisionUser", "identifyUser"])(
    "%s answers with the email, and never reads the key",
    async (route) => {
      const observed = await observe(
        {},
        {
          path: `clickhouse.accesses.${access}.${route}`,
          type: "mutate",
          input: { userBody: EMAIL, context: CONTEXT },
        }
      );

      expect(observed.p0Error).toBeUndefined();
      expect(observed.readSecret).toBe(false);
      expect(observed.cloud.calls).toEqual([]);
      expectSecretContained(observed);
    }
  );
});

// The suffix compared is the secret's own: it's never logged or returned.
describe("a key identified by its secret's last 4 characters", () => {
  it.each(OPERATIONS)("%s", async (_name, operation) => {
    const observed = await sweep(
      {
        setup: (cloud) => {
          const [own] = cloud.keys;
          if (own) own.keySuffix = KEY_SECRET.slice(-4);
        },
      },
      operation
    );

    expect(observed.p0Error).toBeUndefined();
  });
});

// ClickHouse Cloud quoting the request back: its body, and its Authorization header.
const quoting =
  (status: number) =>
  (call: CloudCall): CloudReply =>
    call.host === "queries.clickhouse.cloud"
      ? {
          status,
          body: `Code: 516. DB::Exception: rejected ${call.rawBody ?? ""} sent with ${call.headers.authorization ?? "no credential"}`,
        }
      : {
          status,
          body: {
            status,
            error: `rejected ${call.rawBody ?? ""} sent with ${call.headers.authorization ?? "no credential"}`,
            requestId: call.headers.authorization?.replace(/^Basic /, ""),
          },
        };

const FAILURES: [string, (call: CloudCall) => CloudReply][] = [
  ["400", () => failing(400, "Invalid request")],
  ["400, quoting the request back", quoting(400)],
  ["401", () => failing(401, "Invalid credentials")],
  ["401, quoting the request back", quoting(401)],
  ["403", () => failing(403, "Forbidden")],
  ["403, quoting the request back", quoting(403)],
  ["404", () => failing(404)],
  ["409", () => failing(409, "conflict")],
  ["409, quoting the request back", quoting(409)],
  ["429", () => failing(429, "Too Many Requests", { "retry-after": "1" })],
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
    "a 200 whose rows quote the request back",
    (call) => ({
      status: 200,
      body: `{"auth":${JSON.stringify(call.headers.authorization ?? "")}}\nnot json ${call.headers.authorization ?? ""}\n`,
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

const TARGETS: [string, (call: CloudCall) => boolean][] = [
  ["every Cloud API call", ({ host }) => host === "api.clickhouse.cloud"],
  [
    "every Query API endpoint run",
    ({ host }) => host === "queries.clickhouse.cloud",
  ],
  [
    "the endpoint writes",
    ({ host, method }) => host === "api.clickhouse.cloud" && method !== "GET",
  ],
];

describe.each(
  TARGETS.flatMap(([target, matches]) =>
    FAILURES.map(([answer, reply]) => [answer, target, matches, reply] as const)
  )
)("ClickHouse Cloud answering %s to %s", (_answer, _target, matches, reply) => {
  it.each(OPERATIONS)("%s", async (_name, operation) => {
    await sweep(
      { cloud: (call) => (matches(call) ? reply(call) : undefined) },
      operation
    );
  });
});

// How many characters of a quoted credential come before the 500-character
// cut. A cut made before the key is cut out would keep them.
const KEPT = 10;

const QUOTED_CREDENTIALS: [string, string][] = [
  ["the key secret", KEY_SECRET],
  ["the base64 credentials", base64(`${KEY_ID}:${KEY_SECRET}`)],
  ["the Authorization value", `Basic ${base64(`${KEY_ID}:${KEY_SECRET}`)}`],
];

/** ClickHouse Cloud's message, long, with `credential` across the cut. */
const acrossTheCut =
  (credential: string) =>
  (call: CloudCall): CloudReply => {
    const message = `${"x".repeat(500 - KEPT)}${credential} was rejected`;
    return call.host === "queries.clickhouse.cloud"
      ? { status: 400, body: message }
      : failing(400, message);
  };

describe.each(
  QUOTED_CREDENTIALS.flatMap(([credential, value]) =>
    TARGETS.map(
      ([target, matches]) => [credential, target, matches, value] as const
    )
  )
)(
  "ClickHouse Cloud quoting %s across the 500-character cut, to %s",
  (_credential, _target, matches, value) => {
    it.each(OPERATIONS)("%s", async (_name, operation) => {
      const { outputs, logs } = await sweep(
        {
          cloud: (call) =>
            matches(call) ? acrossTheCut(value)(call) : undefined,
        },
        operation
      );

      expect(
        leaks(
          [...outputs, ...logs],
          [{ name: "its start", value: value.slice(0, KEPT) }]
        )
      ).toEqual([]);
    });
  }
);

const awsError = (name: string, message: string) =>
  Object.assign(new Error(message), {
    name,
    $metadata: { httpStatusCode: 400, requestId: "aws-req-1" },
  });

const VAULT_FAILURES: [string, Error][] = [
  [
    "can't find the secret",
    new SecretNotFoundError("clickhouse-api-key" as SecretRef, {
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

    // Without the key there's nothing to call ClickHouse Cloud with.
    expect(observed.cloud.calls).toEqual([]);
  });
});

const OTHER_SECRET = "9z8ySENTINELotherKeySecret7x6w";

const STORED_SECRETS: [string, Buffer | string][] = [
  ["holds the key with a trailing newline", `${STORED_KEY}\n`],
  ["holds the key as a binary secret", Buffer.from(STORED_KEY, "utf8")],
  [
    "holds another key's secret",
    JSON.stringify({ keyId: KEY_ID, keySecret: OTHER_SECRET }),
  ],
];

describe.each(STORED_SECRETS)("a secret that %s", (_case, stored) => {
  it.each(OPERATIONS)("%s", async (_name, operation) => {
    await sweep({ stored }, operation);
  });
});

// The secret is refused before any call, and never quoted.
const UNUSABLE_SECRETS: [string, string][] = [
  ["holds the bare key secret", KEY_SECRET],
  ["is empty", " \n"],
  [
    "holds the console's field names",
    JSON.stringify({ key_id: KEY_ID, key_secret: KEY_SECRET }),
  ],
  [
    "holds the key secret in an extra field",
    JSON.stringify({ ...JSON.parse(STORED_KEY), note: OTHER_SECRET }),
  ],
  [
    "holds a key secret with a line break",
    JSON.stringify({ keyId: KEY_ID, keySecret: `${KEY_SECRET}\nx` }),
  ],
];

describe.each(UNUSABLE_SECRETS)("a secret that %s", (_case, stored) => {
  it.each(OPERATIONS)("%s", async (_name, operation) => {
    const observed = await observe({ stored }, operation);

    expect(observed.cloud.calls).toEqual([]);
    const secrets = [
      ...secretsOf(STORED_KEY),
      { name: "another key secret", value: OTHER_SECRET },
    ];
    expect(leaks([...observed.outputs, ...observed.logs], secrets)).toEqual([]);
  });
});

describe("the key where the pointer goes", () => {
  it("is refused as the pointer, without being repeated", async () => {
    const observed = await observe(
      {},
      {
        path: "clickhouse.install.validation.get",
        type: "query",
        input: { ...CREDENTIALS, apiKeySecret: STORED_KEY },
      }
    );

    expect(observed.p0Error).toMatchObject({ data: { code: "BAD_REQUEST" } });
    expect(vault.getSecretValue).not.toHaveBeenCalled();
    expectSecretContained(observed);
  });

  // On AWS a secret's name is any string, and the connector never quotes it.
  it("as the secret's name, is never repeated", async () => {
    const observed = await observe(
      { vaultError: new SecretNotFoundError(KEY_SECRET as SecretRef) },
      {
        path: "clickhouse.install.validation.get",
        type: "query",
        input: {
          ...CREDENTIALS,
          apiKeySecret: { ...CREDENTIALS.apiKeySecret, secretId: KEY_SECRET },
        },
      }
    );

    expect(observed.p0Error).toBeDefined();
    expectSecretContained(observed);
  });
});
