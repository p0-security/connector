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
import jwt from "jsonwebtoken";
import { generateKeyPairSync } from "node:crypto";
import { format, inspect } from "node:util";
import type * as pinoModule from "pino";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { handler } from "../index.ts";
import { connectorRouter, t } from "../router.ts";

/**
 * The GitHub App private key, and what's derived from it (the App JWT and the
 * installation tokens), never leave the connector. The key is read from the
 * customer's vault; the JWT and the tokens go to api.github.com only, in the
 * `Authorization` header only. None of them is ever in a response P0 gets, an
 * error, a log line or a request body.
 *
 * Each call is driven through the real router twice: from P0's side, through
 * the Lambda handler, and in-process, for the error the router throws with its
 * whole cause chain.
 */

// `vi.hoisted` guarantees these exist before the (hoisted) `vi.mock` factories run.
const vault = vi.hoisted(() => ({
  createSecretManagerClient: vi.fn(),
  getSecretValue: vi.fn(),
}));
const logged = vi.hoisted(() => ({ lines: [] as string[] }));

vi.mock("@p0security/secret-manager-client", async (importOriginal) => ({
  ...(await importOriginal<typeof secretManagerClient>()),
  createSecretManagerClient: vault.createSecretManagerClient,
}));

// Every logger, the connector's own included, writes here instead of stdout,
// at every level, so a debug line can't hide a leak. The redaction is the real
// one.
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

// Stub the global `fetch` so no real network call is made.
const mockedFetch = vi.fn<typeof fetch>();
vi.stubGlobal("fetch", mockedFetch);

// Like the .pem GitHub generates for an app: PKCS#1, "BEGIN RSA PRIVATE KEY".
const { privateKey: PEM, publicKey } = generateKeyPairSync("rsa", {
  modulusLength: 2048,
  privateKeyEncoding: { type: "pkcs1", format: "pem" },
  publicKeyEncoding: { type: "spki", format: "pem" },
});

const TOKEN = "ghs_CANARY7d1e0f2a9b3c4d5e6f708192a3b4c5";

const LOGIN = "octocat";

const CREDENTIALS = {
  org: "acme",
  appId: "123456",
  privateKey: {
    manager: "aws" as const,
    secretId: "gh-app-key",
    region: "us-west-2",
  },
};

const CONTEXT = { ...CREDENTIALS, requestId: "req-1", githubUserId: "583231" };

type Credential = "App JWT" | "installation token";

type Operation = {
  path: string;
  /** The tRPC client's method for it. */
  type: "mutate" | "query";
  input: unknown;
  /** The credentials a working call sends GitHub, in the order it first sends them. */
  uses: Credential[];
};

const BOTH: Credential[] = ["App JWT", "installation token"];

const operation =
  (type: Operation["type"]) =>
  (path: string, input: unknown, uses: Credential[] = BOTH): Operation => ({
    path: `github-repositories.${path}`,
    type,
    input,
    uses,
  });
const query = operation("query");
const mutation = operation("mutate");

const list = (lookup: Record<string, unknown>) =>
  query("accesses.role.list", { query: { context: CREDENTIALS, ...lookup } });

const setRole = (role: string | null) =>
  mutation("accesses.role.setPoliciesForUser", {
    userId: LOGIN,
    userBody: LOGIN,
    policies: [{ repo: "api", role }],
    context: CONTEXT,
  });

// The router has no `stage`: P0 stages a grant through provisionUser and
// identifyUser, and every grant and revoke is a setPoliciesForUser.
const OPERATIONS: [string, Operation][] = [
  [
    "install validation",
    query("install.validation.get", CREDENTIALS, ["App JWT"]),
  ],
  ["list repositories", list({ type: "repository" })],
  ["list roles", list({ type: "role" })],
  [
    "read a direct role",
    list({ type: "direct-role", repo: "api", login: LOGIN }),
  ],
  [
    "find a member by email",
    list({ type: "member", email: "octocat@acme.com" }),
  ],
  ["look up an account", list({ type: "account", login: LOGIN })],
  [
    "provisionUser",
    mutation("accesses.role.provisionUser", {
      userBody: LOGIN,
      context: CONTEXT,
    }),
  ],
  [
    "identifyUser",
    mutation("accesses.role.identifyUser", {
      userBody: LOGIN,
      context: CONTEXT,
    }),
  ],
  ["grant a role", setRole("push")],
  ["revoke to the prior role", setRole("pull")],
  ["revoke to no role", setRole(null)],
  [
    "deleteUser",
    mutation(
      "accesses.role.deleteUser",
      { userId: LOGIN, userBody: LOGIN, context: CONTEXT },
      []
    ),
  ],
];

type GitHubCall = {
  method: string;
  /** The path and query, e.g. `/installation/repositories?per_page=100&page=1`. */
  path: string;
  credential: Credential;
  body: any;
};

type Reply =
  | { status: number; body?: unknown; headers?: Record<string, string> }
  | { throws: unknown };

const ok = (body: unknown): Reply => ({ status: 200, body });

const INSTALLATION = {
  id: 42,
  permissions: {
    administration: "write",
    metadata: "read",
    members: "read",
    organization_custom_roles: "read",
  },
  repository_selection: "selected",
  suspended_at: null,
};

const ACCOUNT = { id: 583231, login: LOGIN, type: "User" };

const MEMBERS = {
  data: {
    organization: {
      membersWithRole: {
        pageInfo: { endCursor: null, hasNextPage: false },
        nodes: [
          {
            login: LOGIN,
            organizationVerifiedDomainEmails: ["octocat@acme.com"],
          },
        ],
      },
    },
  },
};

const DIRECT_ROLE = {
  data: {
    repository: {
      collaborators: {
        edges: [
          {
            permissionSources: [
              { roleName: "write", source: { __typename: "Repository" } },
            ],
          },
        ],
      },
    },
  },
};

const APP_INVITATION = {
  id: 99,
  invitee: { login: LOGIN },
  inviter: { login: "p0-acme[bot]" },
};

/** GitHub's answers when everything is set up right. */
const answerAsGitHub = ({ method, path, body }: GitHubCall): Reply => {
  const [route] = path.split("?");
  if (method === "DELETE" && route.startsWith("/repos/acme/api/invitations/")) {
    return { status: 204 };
  }
  switch (`${method} ${route}`) {
    case "GET /app":
      return ok({ id: 1, slug: "p0-acme", name: "P0 Acme" });
    case "GET /orgs/acme/installation":
      return ok(INSTALLATION);
    case "POST /app/installations/42/access_tokens":
      return {
        status: 201,
        body: { token: TOKEN, expires_at: "2026-10-02T01:00:00Z" },
      };
    case "GET /installation/repositories":
      return ok({
        total_count: 1,
        repositories: [{ name: "api", full_name: "acme/api" }],
      });
    case "GET /orgs/acme/custom-repository-roles":
      return ok({ total_count: 1, custom_roles: [{ id: 1, name: "Labeler" }] });
    case "GET /orgs/acme":
      return ok({ login: "acme", default_repository_permission: "read" });
    case "GET /orgs/acme/memberships/octocat":
      return ok({ state: "active", role: "member" });
    case "GET /user/583231":
    case "GET /users/octocat":
      return ok(ACCOUNT);
    case "PUT /repos/acme/api/collaborators/octocat":
    case "DELETE /repos/acme/api/collaborators/octocat":
      return { status: 204 };
    case "GET /repos/acme/api/invitations":
      return ok([]);
    case "POST /graphql":
      return ok(
        String(body?.query).includes("membersWithRole") ? MEMBERS : DIRECT_ROLE
      );
    default:
      return { status: 404, body: { message: "Not Found" } };
  }
};

type Sent = {
  url: string;
  method: string;
  /** Lowercased names, as `Headers` gives them. */
  headers: Record<string, string>;
  body: string | undefined;
};

type Scenario = {
  /** GitHub's answer to a call, when it isn't {@link answerAsGitHub}'s. */
  github?: (call: GitHubCall) => Reply | undefined;
  /** What the secret holds: the PEM, unless this says otherwise. */
  stored?: Buffer | string;
  /** How reading the secret fails, if it does. */
  vaultError?: Error;
};

type Observed = {
  /** What P0 got back and what the router returned or threw, rendered every way either might be written out. */
  outputs: string[];
  /** The error P0's client got, if the call failed. */
  p0Error: unknown;
  /** Whether the call asked the vault for the key. */
  readKey: boolean;
  logs: string[];
  requests: Sent[];
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
            (value as Record<string, unknown>)[name],
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

const at = (root: any, path: string): any =>
  path.split(".").reduce((node, key) => node[key], root);

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

const sent: Sent[] = [];

const observe = async (
  { github, stored = PEM, vaultError }: Scenario,
  { path, type, input }: Operation
): Promise<Observed> => {
  logged.lines.length = 0;
  sent.length = 0;
  vault.createSecretManagerClient.mockResolvedValue({
    getSecretValue: vault.getSecretValue,
  });
  if (vaultError) vault.getSecretValue.mockRejectedValue(vaultError);
  else vault.getSecretValue.mockResolvedValue({ value: stored });

  mockedFetch.mockImplementation(async (resource, init) => {
    const request: Sent = {
      url: resource instanceof Request ? resource.url : resource.toString(),
      method: init?.method ?? "GET",
      headers: Object.fromEntries(new Headers(init?.headers)),
      body: init?.body
        ? typeof init.body === "string"
          ? init.body
          : inspect(init.body)
        : undefined,
    };
    sent.push(request);
    const url = new URL(request.url);
    const call: GitHubCall = {
      method: request.method,
      path: `${url.pathname}${url.search}`,
      credential:
        request.headers.authorization === `Bearer ${TOKEN}`
          ? "installation token"
          : "App JWT",
      body: request.body === undefined ? undefined : JSON.parse(request.body),
    };
    const reply = github?.(call) ?? answerAsGitHub(call);
    if ("throws" in reply) throw reply.throws;
    const { status, body, headers } = reply;
    return new Response(
      body === undefined
        ? null
        : typeof body === "string"
          ? body
          : JSON.stringify(body),
      { status, headers }
    );
  });

  const fromP0 = await settle(() => at(p0, path)[type](input));
  const inProcess = await settle(() => at(connector, path)(input));
  return {
    outputs: [fromP0, inProcess].flatMap(({ result, error }) =>
      renderings(error ?? result)
    ),
    p0Error: fromP0.error,
    readKey: vault.getSecretValue.mock.calls.length > 0,
    logs: [...logged.lines],
    requests: [...sent],
  };
};

const bearers = (requests: Sent[]) =>
  requests.map(({ headers }) => headers.authorization?.replace(/^Bearer /, ""));

const credentialsUsed = (requests: Sent[]): Credential[] => [
  ...new Set(
    bearers(requests).map(
      (bearer): Credential =>
        bearer === TOKEN ? "installation token" : "App JWT"
    )
  ),
];

// 16 base64 characters are 96 bits of the key, which nothing else matches by
// chance, so any 32 characters of the body in a row contain a whole slice.
// The first 16 are the ASN.1 header every 2048-bit key starts with.
const SLICE = 16;
const keySlices = (pem: string) => {
  const body = pem.replace(/-----[A-Z ]+-----|\s/g, "");
  return Array.from({ length: Math.floor(body.length / SLICE) - 1 }, (_, i) =>
    body.slice((i + 1) * SLICE, (i + 2) * SLICE)
  );
};

type Secret = { name: string; value: string };

const secretsOf = (stored: string, jwts: string[]): Secret[] => [
  { name: "the private key", value: PEM },
  { name: "the stored secret", value: stored },
  ...keySlices(PEM).map((value) => ({
    name: "a slice of the key's base64 body",
    value,
  })),
  ...jwts.flatMap((value) => [
    { name: "the App JWT", value },
    { name: "the App JWT's signature", value: value.split(".")[2] },
  ]),
  { name: "the installation token", value: TOKEN },
  { name: "the installation token's body", value: TOKEN.slice("ghs_".length) },
];

/** One line per text that holds a secret, naming what it holds. */
const leaks = (texts: string[], secrets: Secret[]) =>
  texts.flatMap((text) => {
    // A JSON line escapes the key's newlines, once or more, and a slice can
    // straddle one.
    const flat = text.replace(/\\+n|\s/g, "");
    const found = new Set(
      secrets
        .filter(({ value }) => text.includes(value) || flat.includes(value))
        .map(({ name }) => name)
    );
    return found.size > 0
      ? [`${[...found].join("; ")}, in: ${text.slice(0, 200)}`]
      : [];
  });

const expectKeyContained = (
  { outputs, logs, requests }: Observed,
  stored: string = PEM
) => {
  const jwts = bearers(requests).filter(
    (bearer): bearer is string => bearer !== undefined && bearer !== TOKEN
  );
  // Anything sent as a credential that isn't the token is a JWT the key signed.
  for (const appJwt of jwts) {
    expect(() =>
      jwt.verify(appJwt, publicKey, { algorithms: ["RS256"] })
    ).not.toThrow();
  }
  const secrets = secretsOf(stored, jwts);

  expect(leaks(outputs, secrets)).toEqual([]);
  expect(leaks(logs, secrets)).toEqual([]);
  // Whatever credential an Authorization header carried, it's never repeated.
  expect([...outputs, ...logs].filter((text) => /bearer/i.test(text))).toEqual(
    []
  );

  for (const { url, headers, body } of requests) {
    expect(new URL(url).origin).toBe("https://api.github.com");
    expect(url.startsWith("https://api.github.com/")).toBe(true);
    const { authorization, ...otherHeaders } = headers;
    expect([
      `Bearer ${TOKEN}`,
      ...jwts.map((appJwt) => `Bearer ${appJwt}`),
    ]).toContain(authorization);
    expect(
      leaks([url, JSON.stringify(otherHeaders), body ?? ""], secrets)
    ).toEqual([]);
  }
};

/** {@link observe}, for a call that gets as far as the key, then checks it went no further. */
const sweep = async (
  scenario: Scenario,
  operation: Operation,
  stored = scenario.stored?.toString("utf8")
) => {
  const observed = await observe(scenario, operation);
  // A call refused before it reads the key proves nothing about the key.
  expect(observed.readKey).toBe(operation.uses.length > 0);
  expectKeyContained(observed, stored);
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
      // Otherwise nothing derived from the key was in play, and this proves
      // nothing.
      expect(credentialsUsed(observed.requests)).toEqual(operation.uses);
      // Nor if the connector's log lines weren't the ones checked.
      expect(observed.logs).not.toEqual([]);
    }
  );
});

const failing = (
  status: number,
  body?: unknown,
  headers?: Record<string, string>
) => ({ status, body, headers });

const GITHUB_FAILURES: [string, () => Reply][] = [
  ["401", () => failing(401, { message: "Bad credentials" })],
  [
    "403 for a missing permission",
    () =>
      failing(
        403,
        { message: "Resource not accessible by integration" },
        { "X-Accepted-GitHub-Permissions": "administration=write" }
      ),
  ],
  [
    "403 for a suspended installation",
    () => failing(403, { message: "This installation has been suspended" }),
  ],
  [
    "403 for a secondary rate limit",
    () =>
      failing(403, {
        message:
          "You have exceeded a secondary rate limit. Please wait a few minutes before you try again.",
      }),
  ],
  ["404", () => failing(404, { message: "Not Found" })],
  [
    "422",
    () =>
      failing(422, {
        message: "Validation Failed",
        errors: [{ resource: "Repository", code: "custom", message: "x" }],
      }),
  ],
  ["500", () => failing(500, "")],
  ["502 with an HTML page", () => failing(502, "<html>Unicorn!</html>")],
  [
    "nothing, the network failing",
    () => ({
      throws: new TypeError("fetch failed", {
        cause: Object.assign(
          new Error("connect ECONNREFUSED 140.82.112.6:443"),
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
];

describe.each(
  BOTH.flatMap((credential) =>
    GITHUB_FAILURES.map(
      ([answer, reply]) => [answer, credential, reply] as const
    )
  )
)(
  "GitHub answering %s to calls made with the %s",
  (_answer, credential, reply) => {
    it.each(OPERATIONS)("%s", async (_name, operation) => {
      await sweep(
        {
          github: (call) =>
            call.credential === credential ? reply() : undefined,
        },
        operation
      );
    });
  }
);

const graphqlErrors = (errors: unknown[]) => (call: GitHubCall) =>
  call.path === "/graphql" ? ok({ data: null, errors }) : undefined;

const notAMember = (call: GitHubCall) =>
  call.path === "/orgs/acme/memberships/octocat"
    ? failing(404, { message: "Not Found" })
    : undefined;

const GITHUB_ANSWERS: [string, (call: GitHubCall) => Reply | undefined][] = [
  [
    "a typed GraphQL error in a 200",
    graphqlErrors([
      {
        type: "NOT_FOUND",
        path: ["repository"],
        message: "Could not resolve to a Repository with the name 'acme/api'.",
      },
    ]),
  ],
  [
    "an untyped GraphQL error in a 200",
    graphqlErrors([
      { message: "Something went wrong while executing your query." },
    ]),
  ],
  [
    "a token refused for a repo outside the selection",
    (call) =>
      call.path.endsWith("/access_tokens")
        ? failing(422, {
            message:
              "There is at least one repository that does not exist or is not accessible to the parent installation.",
          })
        : undefined,
  ],
  [
    "a suspended installation",
    (call) =>
      call.path === "/orgs/acme/installation"
        ? ok({ ...INSTALLATION, suspended_at: "2026-09-01T00:00:00Z" })
        : undefined,
  ],
  [
    "an installation missing permissions",
    (call) =>
      call.path === "/orgs/acme/installation"
        ? ok({ ...INSTALLATION, permissions: { metadata: "read" } })
        : undefined,
  ],
  [
    "no account behind the user id or login",
    (call) =>
      /^\/users?\//.test(call.path)
        ? failing(404, { message: "Not Found" })
        : undefined,
  ],
  ["a user who isn't an org member", notAMember],
  [
    "a pending invitation from the app to a non-member",
    (call) =>
      notAMember(call) ??
      (call.method === "GET" &&
      call.path.startsWith("/repos/acme/api/invitations")
        ? ok([APP_INVITATION])
        : undefined),
  ],
  [
    "a role PUT that became an invitation",
    (call) =>
      call.method === "PUT" ? { status: 201, body: APP_INVITATION } : undefined,
  ],
];

describe.each(GITHUB_ANSWERS)("GitHub answering with %s", (_answer, github) => {
  it.each(OPERATIONS)("%s", async (_name, operation) => {
    await sweep({ github }, operation);
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
    new SecretNotFoundError("gh-app-key" as SecretRef, {
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

    // Without the key there's nothing to call GitHub with.
    expect(observed.requests).toEqual([]);
  });
});

const STORED_SECRETS: [string, Buffer | string][] = [
  ["isn't a PEM", "SENTINEL-not-a-pem-7f3a9c"],
  [
    "is a truncated PEM",
    `${PEM.slice(0, Math.floor(PEM.length / 2))}\n-----END RSA PRIVATE KEY-----`,
  ],
  [
    "holds the PEM as a JSON key/value pair",
    JSON.stringify({ "github-app-key": PEM }),
  ],
  ["holds the PEM with escaped newlines", PEM.replace(/\n/g, "\\n")],
  ["holds the PEM as a binary secret", Buffer.from(PEM, "utf8")],
];

describe.each(STORED_SECRETS)("a secret that %s", (_case, stored) => {
  it.each(OPERATIONS)("%s", async (_name, operation) => {
    await sweep({ stored }, operation);
  });
});

describe("key material where the pointer goes", () => {
  const repositories = (privateKey: unknown) =>
    query("accesses.role.list", {
      query: { type: "repository", context: { ...CREDENTIALS, privateKey } },
    });

  it("refuses the PEM itself as the pointer, without repeating it", async () => {
    const observed = await observe({}, repositories(PEM));

    expect(observed.p0Error).toMatchObject({ data: { code: "BAD_REQUEST" } });
    expect(vault.getSecretValue).not.toHaveBeenCalled();
    expectKeyContained(observed);
  });

  // The secret id is any non-empty string, so a key pasted into it is sent to
  // the vault as a name, and the not-found message quotes it back to P0 and
  // into the connector's logs.
  it.fails("never repeats a PEM pasted where the secret id goes", async () => {
    const observed = await observe(
      { vaultError: new SecretNotFoundError(PEM as SecretRef) },
      repositories({ ...CREDENTIALS.privateKey, secretId: PEM })
    );

    expectKeyContained(observed);
  });
});
