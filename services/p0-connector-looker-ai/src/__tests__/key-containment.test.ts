import { createLogger } from "@p0security/connector-core";
import type * as secretManagerClient from "@p0security/connector-secret-manager-client";
import { format, inspect } from "node:util";
import type * as pinoModule from "pino";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { handler } from "../index.ts";
import { connectorRouter } from "../router.ts";

/**
 * The Looker Admin API key, the access token it signs in for, and each grant's
 * Looker API key never leave the connector, except that the Admin key and its
 * token go to the Looker instance, and the grant's key goes to the grant's
 * secret. None of them is ever in a response P0 gets, an error or a log line.
 *
 * Each call is driven through the real router twice: from P0's side, through
 * the cloud function handler, and in-process, for the error the router throws
 * with its whole cause chain.
 */

// `vi.hoisted` guarantees these exist before the (hoisted) `vi.mock` factories run.
const vault = vi.hoisted(() => ({ createSecretManagerClient: vi.fn() }));
const logged = vi.hoisted(() => ({ lines: [] as string[] }));

vi.mock(
  "@p0security/connector-secret-manager-client",
  async (importOriginal) => ({
    ...(await importOriginal<typeof secretManagerClient>()),
    createSecretManagerClient: vault.createSecretManagerClient,
  })
);

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

const BASE_URL = "https://example.looker.app";

const ADMIN_KEY = {
  client_id: "admin-client-id",
  client_secret: "CANARYadminsecret7d1e0f2a9b3c",
};
const ADMIN_TOKEN = "CANARYadmintoken4d5e6f708192";
const GRANT_KEY = {
  client_id: "grantclientid",
  client_secret: "CANARYgrantsecreta3b4c5d6e7f8",
};
// What the connector writes to the grant's secret, and how Secret Manager's
// API carries it.
const GRANT_KEY_VALUE = `${GRANT_KEY.client_id}:${GRANT_KEY.client_secret}`;
const GRANT_KEY_BASE64 = Buffer.from(GRANT_KEY_VALUE).toString("base64");

const SECRETS = {
  "the Admin key's client secret": ADMIN_KEY.client_secret,
  "the Admin key's access token": ADMIN_TOKEN,
  "the grant key's client secret": GRANT_KEY.client_secret,
  "the grant key, as Secret Manager carries it": GRANT_KEY_BASE64,
};

const GRANT = "p0_access-token_looker_acme_1a2b3c4d";

const INSTANCE = {
  baseUrl: BASE_URL,
  secrets: {
    manager: "gcp" as const,
    adminKeySecretId: "p0_install_looker_acme_admin-key",
    projectId: "acme-prod",
  },
};

const CONTEXT = { requestId: "r-1", ...INSTANCE, contentFolderId: "7" };

type Reply = { status: number; body?: unknown } | { throws: unknown };

const ok = (body: unknown): Reply => ({ status: 200, body });

type Scenario = {
  /** Whether the grant's Looker service account exists already. */
  accountExists?: boolean;
  /** Looker's answer to a call, when it isn't {@link answerAsLooker}'s. */
  looker?: (call: string) => Reply | undefined;
  /** What the Admin key secret holds, when it isn't the key as JSON. */
  storedAdminKey?: string;
  /** Whether writing the grant's secret fails. */
  writeFails?: boolean;
  /** Whether deleting the grant's secret fails. */
  deleteFails?: boolean;
};

const PERMISSIONS = [
  { permission: "access_data", parent: null },
  { permission: "see_looks", parent: "access_data" },
  { permission: "see_user_dashboards", parent: "see_looks" },
  { permission: "see_lookml_dashboards", parent: "access_data" },
  { permission: "explore", parent: "see_looks" },
  { permission: "see_sql", parent: "access_data" },
  { permission: "save_content", parent: "see_looks" },
  { permission: "save_looks", parent: "see_looks" },
  { permission: "save_dashboards", parent: "see_user_dashboards" },
];

const ROLE_ID = "13";

/** Looker's answers when everything is set up right. A create answers with
 * what it was sent. */
const answerAsLooker = (
  call: string,
  scenario: Scenario,
  body: Record<string, unknown>
): Reply => {
  switch (call) {
    case "GET /permissions":
      return ok(PERMISSIONS);
    case "GET /permission_sets/search":
    case "GET /model_sets/search":
    case "GET /roles/search":
    case "GET /content_metadata_access":
      return ok([]);
    case "POST /permission_sets":
      return ok({ id: "11", ...body });
    case "POST /model_sets":
      return ok({ id: "12", ...body });
    case "POST /roles":
      return ok({
        id: ROLE_ID,
        name: body.name,
        permission_set: { id: body.permission_set_id },
        model_set: { id: body.model_set_id },
      });
    case "PUT /users/42/roles":
    case "GET /users/42/roles":
      return ok([{ id: ROLE_ID }]);
    case "GET /folders/7":
      return ok({ id: "7", content_metadata_id: "70" });
    case "POST /content_metadata_access":
      return ok({ id: "5" });
    case "GET /lookml_models":
      return ok([{ name: "thelook", label: "The Look" }]);
    case "GET /groups/search/with_roles":
      return ok([
        {
          id: "1",
          name: "All Users",
          include_by_default: true,
          roles: [{ name: "Viewer" }],
        },
      ]);
    case "POST /login":
      return ok({
        access_token: ADMIN_TOKEN,
        token_type: "Bearer",
        expires_in: 3600,
      });
    case "DELETE /logout":
    case "DELETE /users/service_accounts/42":
      return { status: 204 };
    case "GET /users/search":
      return ok(
        scenario.accountExists
          ? [{ id: "42", service_account_name: GRANT, first_name: "P0" }]
          : []
      );
    case "POST /users/service_accounts":
    case "PATCH /users/42":
      return ok({ id: "42" });
    case "POST /users/42/credentials_api3":
      return ok({ id: "7", ...GRANT_KEY });
    default:
      return { status: 404, body: { message: "Not found" } };
  }
};

/**
 * An error like the one Google's client throws for a failed call: it holds
 * the request, body and headers included.
 */
const requestError = (value?: Buffer) => {
  const config = {
    url: "https://secretmanager.googleapis.com/v1/projects/acme-prod/secrets/s",
    headers: { authorization: "Bearer adc-token" },
    ...(value
      ? {
          data: { payload: { data: value.toString("base64") } },
          body: JSON.stringify({ payload: { data: value.toString("base64") } }),
        }
      : {}),
  };
  return Object.assign(new Error("Internal error encountered."), {
    config,
    response: { status: 500, config },
  });
};

type Sent = { url: string; headers: Record<string, string>; body: string };

type Observed = {
  /** What P0 got back and what the router returned or threw, rendered every way either might be written out. */
  outputs: string[];
  logs: string[];
  requests: Sent[];
  /** What was written to the grant's secret. */
  written: string[];
  /** What the router returned, or threw, in-process. */
  inProcess: { result?: unknown; error?: unknown };
  /** The HTTP status P0 got. */
  status: number;
};

/** Every way a value might be written out, down its cause chain. */
const renderings = (value: unknown): string[] => {
  const rendered: string[] = [];
  for (
    let current = value, depth = 0;
    current !== undefined && current !== null && depth < 10;
    current = (current as { cause?: unknown }).cause, depth++
  ) {
    rendered.push(inspect(current, { depth: Infinity, showHidden: true }));
    try {
      rendered.push(JSON.stringify(current) ?? "");
    } catch {
      // Not serializable, so it can't be written out this way.
    }
  }
  return rendered;
};

type Call = {
  /** The procedure's path under `looker-ai` */
  path: string;
  kind: "mutation" | "query";
  input: unknown;
};

const model = (procedure: string, kind: Call["kind"], input: unknown) => ({
  path: `accesses.model.${procedure}`,
  kind,
  input,
});

const OPERATIONS = {
  provisionUser: model("provisionUser", "mutation", {
    userBody: GRANT,
    context: CONTEXT,
  }),
  identifyUser: model("identifyUser", "mutation", {
    userBody: GRANT,
    context: CONTEXT,
  }),
  deleteUser: model("deleteUser", "mutation", {
    userId: GRANT,
    userBody: GRANT,
    context: CONTEXT,
  }),
  grant: model("setPoliciesForUser", "mutation", {
    userId: GRANT,
    userBody: GRANT,
    policies: [{ model: "thelook", level: "edit" }],
    context: CONTEXT,
  }),
  revoke: model("setPoliciesForUser", "mutation", {
    userId: GRANT,
    userBody: GRANT,
    policies: [null],
    context: CONTEXT,
  }),
  list: model("list", "query", { query: { type: "model", context: INSTANCE } }),
  validateInstall: {
    path: "install.validation.get",
    kind: "query",
    input: { ...INSTANCE, contentFolderId: "7" },
  },
} satisfies Record<string, Call>;

type Operation = keyof typeof OPERATIONS;

/** Calls a procedure in-process, by its path. */
const callInProcess = (root: unknown, { path, input }: Call) => {
  const procedure = path
    .split(".")
    .reduce((node, key) => (node as Record<string, unknown>)[key], root) as (
    input: unknown
  ) => Promise<unknown>;
  return procedure(input);
};

const observe = async (
  operation: Operation,
  scenario: Scenario
): Promise<Observed> => {
  const requests: Sent[] = [];
  const written: string[] = [];

  mockedFetch.mockImplementation(async (input, init) => {
    // The connector passes the URL as a string.
    const url = typeof input === "string" ? input : "";
    requests.push({
      url,
      headers: Object.fromEntries(new Headers(init?.headers)),
      body: typeof init?.body === "string" ? init.body : "",
    });
    const route = new URL(url).pathname.replace("/api/4.0", "");
    const call = `${init?.method} ${route}`;
    const sent =
      typeof init?.body === "string" && init.body.startsWith("{")
        ? (JSON.parse(init.body) as Record<string, unknown>)
        : {};
    const reply =
      scenario.looker?.(call) ?? answerAsLooker(call, scenario, sent);
    if ("throws" in reply) throw reply.throws;
    return new Response(
      reply.body === undefined ? null : JSON.stringify(reply.body),
      { status: reply.status }
    );
  });

  vault.createSecretManagerClient.mockResolvedValue({
    getSecretValue: async () => ({
      value: scenario.storedAdminKey ?? JSON.stringify(ADMIN_KEY),
    }),
    createSecret: async ({ name }: { name: string }) => ({ ref: name, name }),
    createSecretVersion: async ({ value }: { value: Buffer }) => {
      if (scenario.writeFails) throw requestError(value);
      written.push(value.toString("utf8"));
    },
    deleteSecret: async () => {
      if (scenario.deleteFails) throw requestError();
    },
  });

  const call: Call = OPERATIONS[operation];
  const root = connectorRouter.createCaller({ logger: createLogger() })[
    "looker-ai"
  ];
  const inProcess = await callInProcess(root, call).then(
    (result) => ({ result }),
    (error: unknown) => ({ error })
  );

  const url = `https://connector.test/trpc/looker-ai.${call.path}`;
  const fromP0 = await handler(
    call.kind === "query"
      ? {
          url: `${url}?input=${encodeURIComponent(JSON.stringify(call.input))}`,
          method: "GET",
          headers: {},
        }
      : {
          url,
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify(call.input),
        }
  );

  return {
    outputs: [...renderings(inProcess), ...renderings(fromP0)],
    inProcess,
    status: fromP0.status,
    logs: [...logged.lines],
    requests,
    written,
  };
};

const lookerFails = (failing: string, reply: Reply) => (call: string) =>
  call === failing ? reply : undefined;

const SERVER_ERROR: Reply = {
  status: 500,
  body: { message: "An error occurred" },
};
const NETWORK_ERROR: Reply = { throws: new TypeError("fetch failed") };

const PROVISION_CALLS = [
  "POST /login",
  "GET /users/search",
  "POST /users/service_accounts",
  "PATCH /users/42",
  "POST /users/42/credentials_api3",
  "DELETE /logout",
];

const GRANT_CALLS = [
  "GET /permissions",
  "GET /permission_sets/search",
  "POST /permission_sets",
  "GET /model_sets/search",
  "POST /model_sets",
  "GET /roles/search",
  "POST /roles",
  "PUT /users/42/roles",
  "GET /users/42/roles",
  "GET /folders/7",
  "GET /content_metadata_access",
  "POST /content_metadata_access",
];

const SCENARIOS: [string, Operation, Scenario][] = [
  ["provisionUser", "provisionUser", {}],
  [
    "provisionUser of an existing account",
    "provisionUser",
    { accountExists: true },
  ],
  ...PROVISION_CALLS.flatMap((call): [string, Operation, Scenario][] => [
    [
      `provisionUser when Looker fails ${call}`,
      "provisionUser",
      { looker: lookerFails(call, SERVER_ERROR) },
    ],
    [
      `provisionUser when Looker can't be reached for ${call}`,
      "provisionUser",
      { looker: lookerFails(call, NETWORK_ERROR) },
    ],
  ]),
  [
    "provisionUser when the secret can't be written",
    "provisionUser",
    { writeFails: true },
  ],
  [
    "provisionUser when the secret can't be written, nor the account deleted",
    "provisionUser",
    {
      writeFails: true,
      looker: lookerFails("DELETE /users/service_accounts/42", SERVER_ERROR),
    },
  ],
  [
    "provisionUser when Looker returns a key with a line break",
    "provisionUser",
    {
      looker: lookerFails(
        "POST /users/42/credentials_api3",
        ok({
          id: "7",
          ...GRANT_KEY,
          client_secret: `${GRANT_KEY.client_secret}\n`,
        })
      ),
    },
  ],
  [
    "provisionUser when the Admin key secret is not JSON",
    "provisionUser",
    { storedAdminKey: `${ADMIN_KEY.client_id}:${ADMIN_KEY.client_secret}` },
  ],
  [
    "provisionUser when Looker does not accept the Admin key",
    "provisionUser",
    {
      looker: lookerFails("POST /login", {
        status: 404,
        body: { message: "Not found" },
      }),
    },
  ],
  ["identifyUser", "identifyUser", { accountExists: true }],
  ["setPoliciesForUser for an edit grant", "grant", { accountExists: true }],
  ...GRANT_CALLS.flatMap((call): [string, Operation, Scenario][] => [
    [
      `setPoliciesForUser when Looker fails ${call}`,
      "grant",
      { accountExists: true, looker: lookerFails(call, SERVER_ERROR) },
    ],
    [
      `setPoliciesForUser when Looker can't be reached for ${call}`,
      "grant",
      { accountExists: true, looker: lookerFails(call, NETWORK_ERROR) },
    ],
  ]),
  [
    "setPoliciesForUser when Looker reports other roles",
    "grant",
    {
      accountExists: true,
      looker: lookerFails(
        "GET /users/42/roles",
        ok([{ id: ROLE_ID }, { id: "1" }])
      ),
    },
  ],
  ["setPoliciesForUser for no access", "revoke", { accountExists: true }],
  ["list", "list", {}],
  [
    "list when Looker fails",
    "list",
    { looker: lookerFails("GET /lookml_models", SERVER_ERROR) },
  ],
  ["install validation", "validateInstall", {}],
  [
    "install validation when Looker does not accept the Admin key",
    "validateInstall",
    {
      looker: lookerFails("POST /login", {
        status: 404,
        body: { message: "Not found" },
      }),
    },
  ],
  [
    "install validation when Looker fails",
    "validateInstall",
    { looker: lookerFails("GET /groups/search/with_roles", SERVER_ERROR) },
  ],
  ["deleteUser", "deleteUser", { accountExists: true }],
  [
    "deleteUser when the secret can't be deleted",
    "deleteUser",
    { accountExists: true, deleteFails: true },
  ],
];

beforeEach(() => {
  vi.clearAllMocks();
  logged.lines.length = 0;
});

describe("the fakes", () => {
  // Otherwise the checks below would pass without proving anything.
  it("log through the recorded logger", () => {
    createLogger().info("a line");

    expect(logged.lines.join("")).toContain("a line");
  });

  it("fail a secret write with an error that holds the key", () => {
    expect(
      renderings(requestError(Buffer.from(GRANT_KEY_VALUE))).join("")
    ).toContain(GRANT_KEY_BASE64);
  });
});

describe.each(SCENARIOS)("%s", (_, operation, scenario) => {
  it.each(Object.entries(SECRETS))(
    "keeps %s out of logs, errors and responses",
    async (_, secret) => {
      const { outputs, logs } = await observe(operation, scenario);

      expect(logs.length).toBeGreaterThan(0);
      expect(logs.join("\n")).not.toContain(secret);
      expect(outputs.join("\n")).not.toContain(secret);
    }
  );

  it("sends the Admin key to the instance's /login only, and its token to the instance only", async () => {
    const { requests } = await observe(operation, scenario);

    for (const { url, headers, body } of requests) {
      const sent = `${url}\n${JSON.stringify(headers)}\n${body}`;
      expect(url.startsWith(`${BASE_URL}/api/4.0/`)).toBe(true);
      expect(url).not.toContain(ADMIN_KEY.client_secret);
      expect(sent).not.toContain(GRANT_KEY.client_secret);
      if (url !== `${BASE_URL}/api/4.0/login`) {
        expect(sent).not.toContain(ADMIN_KEY.client_secret);
        expect(`${url}\n${body}`).not.toContain(ADMIN_TOKEN);
      }
    }
  });
});

describe("the grant's key", () => {
  it("is written to the grant's secret, and nowhere else", async () => {
    const { written, outputs } = await observe("provisionUser", {});

    // Once in-process, and once through the handler.
    expect(written).toEqual([GRANT_KEY_VALUE, GRANT_KEY_VALUE]);
    // The user id is the secret's name.
    expect(outputs.join("\n")).toContain(GRANT);
  });
});

// Otherwise the checks above could pass on calls that fail before they reach
// the code that handles a key.
describe.each<[Operation, unknown]>([
  ["grant", null],
  ["revoke", null],
  ["list", [{ key: "thelook", value: "The Look" }]],
  [
    "validateInstall",
    {
      adminKeyAccepted: true,
      models: 1,
      missingPermissions: [],
      refusedPermissions: [],
      inheritedRoles: [{ group: "All Users", roles: ["Viewer"] }],
      contentFolderFound: true,
    },
  ],
])("%s, when everything is set up right", (operation, expected) => {
  it("succeeds in-process and from P0", async () => {
    const { inProcess, status } = await observe(operation, {
      accountExists: true,
    });

    expect(inProcess).toEqual({ result: expected });
    expect(status).toBe(200);
  });
});

describe("an edit grant", () => {
  it("gives the account P0's role and edit access on the folder", async () => {
    const { requests } = await observe("grant", { accountExists: true });

    const sent = requests.map(({ url, body }) => ({
      call: new URL(url).pathname.replace("/api/4.0", ""),
      body,
    }));
    expect(sent).toContainEqual({ call: "/users/42/roles", body: '["13"]' });
    expect(sent).toContainEqual({
      call: "/content_metadata_access",
      body: '{"content_metadata_id":"70","user_id":"42","permission_type":"edit"}',
    });
  });
});
