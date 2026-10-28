import type * as Sts from "@aws-sdk/client-sts";
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

import type { TailscaleConnectorRouter } from "../connector.ts";
import { newTailscaleRouter, t } from "../router.ts";
import { resetTokenCache } from "../tailscale/client.ts";
import {
  type FakeTailscale,
  type TailscaleCall,
  type TailscaleReply,
  failing,
} from "./fake-tailscale.ts";
import {
  CLIENT_ID,
  CLIENT_SECRET,
  CREDENTIALS,
  FEDERATED_CREDENTIAL,
  fakeIdentityToken,
  identityTokenFor,
} from "./fixtures.ts";
import { OPERATIONS, type Operation } from "./operations.ts";
import { newTestTailnet } from "./tailnet.ts";

/**
 * The OAuth client's secret, the cloud identity token and the access tokens
 * Tailscale issues never leave the connector. The secret goes to Tailscale's
 * token endpoint only, in the form body only; the identity token to the
 * token exchange only; an access token to the API only, in the
 * `Authorization` header only. None is ever in a response P0 gets, an error,
 * a log line, a URL or another request.
 *
 * Each call is driven through the real router twice: from P0's side, through
 * the Lambda handler, and in-process, for the error the router throws with
 * its whole cause chain.
 */

const vault = vi.hoisted(() => ({
  createSecretManagerClient: vi.fn(),
  getSecretValue: vi.fn(),
}));
const logged = vi.hoisted((): { lines: string[] } => ({ lines: [] }));
const stsSend = vi.hoisted(() => vi.fn());

vi.mock("@p0security/secret-manager-client", async (importOriginal) => ({
  ...(await importOriginal<typeof secretManagerClient>()),
  createSecretManagerClient: vault.createSecretManagerClient,
}));

vi.mock("@aws-sdk/client-sts", async (importOriginal) => ({
  ...(await importOriginal<typeof Sts>()),
  STSClient: class {
    send = stsSend;
  },
  GetWebIdentityTokenCommand: class {
    constructor(readonly input: unknown) {}
  },
}));

// Every logger writes here instead of stdout, at every level, so a debug line
// can't hide a leak.
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

const { handler } = await import("../index.ts");

type Observed = {
  outputs: string[];
  p0Error: unknown;
  logs: string[];
  tailnet: FakeTailscale;
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

/** Calls the procedure at a dotted path on a tRPC client or caller. */
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

// P0's side of the wire: a tRPC client invoking the Lambda handler.
const p0 = newTRPCConnectorClient<TailscaleConnectorRouter>({
  links: [
    newCloudFunctionLink(
      async (input) =>
        new TextEncoder().encode(
          JSON.stringify(await handler(JSON.parse(input)))
        ).buffer
    ),
  ],
});
const connector = t.createCallerFactory(
  newTailscaleRouter({ identityToken: fakeIdentityToken })
)({ logger: createLogger() });

type Scenario = {
  tailscale?: (call: TailscaleCall) => TailscaleReply | undefined;
  stored?: string;
  vaultError?: Error;
};

const observe = async (
  { tailscale, stored = CLIENT_SECRET, vaultError }: Scenario,
  { path, type, input }: Operation
): Promise<Observed> => {
  logged.lines.length = 0;
  resetTokenCache();
  vault.createSecretManagerClient.mockResolvedValue({
    getSecretValue: vault.getSecretValue,
  });
  if (vaultError) vault.getSecretValue.mockRejectedValue(vaultError);
  else {
    vault.getSecretValue.mockResolvedValue({
      value: stored,
      version: { ref: "tailscale-oauth-client/versions/1" },
    });
  }
  stsSend.mockImplementation(
    async (command: { input: { Audience: string[] } }) => ({
      WebIdentityToken: identityTokenFor(command.input.Audience[0] ?? ""),
    })
  );
  const tailnet = newTestTailnet();
  if (tailscale) tailnet.intercept(tailscale);

  const fromP0 = await settle(() => invoke(p0, `${path}.${type}`, input));
  resetTokenCache();
  const inProcess = await settle(() => invoke(connector, path, input));
  return {
    outputs: [fromP0, inProcess].flatMap(({ result, error }) =>
      renderings(error ?? result)
    ),
    p0Error: fromP0.error,
    logs: [...logged.lines],
    tailnet,
  };
};

type Secret = { name: string; value: string };

const IDENTITY_TOKEN = identityTokenFor(
  `api.tailscale.com/${FEDERATED_CREDENTIAL.clientId}`
);

const secretsOf = (stored: string, tokens: string[]): Secret[] => [
  { name: "the client secret", value: CLIENT_SECRET },
  { name: "the stored secret", value: stored },
  { name: "the identity token", value: IDENTITY_TOKEN },
  { name: "the identity token's signature", value: "SENTINELsig" },
  ...tokens.map((value) => ({ name: "an access token", value })),
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

const expectSecretsContained = (
  { outputs, logs, tailnet }: Observed,
  stored: string = CLIENT_SECRET
) => {
  const secrets = secretsOf(stored.trim(), tailnet.tokens);

  expect(leaks(outputs, secrets)).toEqual([]);
  expect(leaks(logs, secrets)).toEqual([]);
  expect([...outputs, ...logs].filter((text) => /bearer/i.test(text))).toEqual(
    []
  );

  for (const { url, path, headers, rawBody, form, redirect } of tailnet.calls) {
    expect(url.startsWith("https://api.tailscale.com/")).toBe(true);
    expect(redirect).toBe("error");
    const { authorization, ...otherHeaders } = headers;
    if (path === "/api/v2/oauth/token") {
      expect(authorization).toBeUndefined();
      expect(form?.client_id).toBe(CLIENT_ID);
      expect(form?.client_secret).toBe(stored.trim());
      expect(leaks([url, JSON.stringify(otherHeaders)], secrets)).toEqual([]);
    } else if (path === "/api/v2/oauth/token-exchange") {
      expect(authorization).toBeUndefined();
      expect(form).toEqual({
        client_id: FEDERATED_CREDENTIAL.clientId,
        jwt: IDENTITY_TOKEN,
      });
      expect(leaks([url, JSON.stringify(otherHeaders)], secrets)).toEqual([]);
    } else {
      expect(tailnet.tokens.map((token) => `Bearer ${token}`)).toContain(
        authorization
      );
      expect(
        leaks([url, JSON.stringify(otherHeaders), rawBody ?? ""], secrets)
      ).toEqual([]);
    }
  }
};

const sweep = async (scenario: Scenario, operation: Operation) => {
  const observed = await observe(scenario, operation);
  expectSecretsContained(observed, scenario.stored);
  return observed;
};

beforeEach(() => {
  vi.clearAllMocks();
});

describe("a working install", () => {
  it.each(OPERATIONS)(
    "%s succeeds, and the secrets stay in the connector",
    async (_name, operation) => {
      const observed = await sweep({}, operation);

      expect(observed.p0Error).toBeUndefined();
      expect(observed.tailnet.exchanges().length).toBeGreaterThan(0);
      expect(observed.logs).not.toEqual([]);
    }
  );
});

// Tailscale quoting the request back: its body, and its Authorization header.
const quoting =
  (status: number) =>
  (call: TailscaleCall): TailscaleReply => ({
    status,
    body: {
      message: `rejected ${call.rawBody ?? ""} sent with ${call.headers.authorization ?? "no credential"}`,
      error_description: call.headers.authorization?.replace(/^Bearer /, ""),
    },
  });

const FAILURES: [string, (call: TailscaleCall) => TailscaleReply][] = [
  ["400", () => failing(400, "invalid request")],
  ["400, quoting the request back", quoting(400)],
  ["401", () => failing(401, "invalid token")],
  ["401, quoting the request back", quoting(401)],
  ["402, quoting the request back", quoting(402)],
  ["403", () => failing(403, "forbidden")],
  ["403, quoting the request back", quoting(403)],
  ["404", () => failing(404, "not found")],
  ["412, quoting the request back", quoting(412)],
  ["429", () => failing(429, "too many requests", { "retry-after": "5" })],
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
      body: { unexpected: call.headers.authorization, echoed: call.rawBody },
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
    "nothing, fetch quoting the request's Authorization header",
    (call) => ({
      throws: new TypeError(
        `Headers.append: "${call.headers.authorization ?? "no credential"}" is an invalid header value.`
      ),
    }),
  ],
  [
    "nothing, fetch quoting the request's body",
    (call) => ({ throws: new TypeError(`could not send ${call.rawBody}`) }),
  ],
];

const TARGETS: [string, (call: TailscaleCall) => boolean][] = [
  ["the token exchanges", ({ path }) => path.startsWith("/api/v2/oauth/")],
  [
    "every call that carries an access token",
    ({ path }) => !path.startsWith("/api/v2/oauth/"),
  ],
];

describe.each(
  TARGETS.flatMap(([target, matches]) =>
    FAILURES.map(([answer, reply]) => [answer, target, matches, reply] as const)
  )
)("Tailscale answering %s to %s", (_answer, _target, matches, reply) => {
  it.each(OPERATIONS)("%s", async (_name, operation) => {
    await sweep(
      { tailscale: (call) => (matches(call) ? reply(call) : undefined) },
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
    new SecretNotFoundError("tailscale-oauth-client" as SecretRef, {
      cause: awsError("ResourceNotFoundException", "not found"),
    }),
  ],
  [
    "won't let the connector read it",
    new UnauthorizedError("aws", {
      cause: awsError("AccessDeniedException", "not authorized"),
    }),
  ],
];

describe.each(VAULT_FAILURES)("a vault that %s", (_case, vaultError) => {
  it.each(OPERATIONS.filter(([, { vault }]) => vault))(
    "%s",
    async (_name, operation) => {
      const observed = await sweep({ vaultError }, operation);
      expect(observed.tailnet.calls).toEqual([]);
    }
  );
});

describe("a secret that holds another client's secret", () => {
  it.each(OPERATIONS.filter(([, { vault }]) => vault))(
    "%s",
    async (_name, operation) => {
      await sweep({ stored: "tskey-client-SENTINELother9c1f" }, operation);
    }
  );
});

describe("the secret where the pointer goes", () => {
  it("is refused as the pointer, without being repeated", async () => {
    const observed = await observe(
      {},
      {
        path: "tailscale.install.validation.get",
        type: "query",
        vault: true,
        input: {
          ...CREDENTIALS,
          credential: {
            kind: "vault",
            clientId: CLIENT_ID,
            secret: CLIENT_SECRET,
          },
        },
      }
    );

    expect(observed.p0Error).toMatchObject({ data: { code: "BAD_REQUEST" } });
    expect(vault.getSecretValue).not.toHaveBeenCalled();
    expectSecretsContained(observed);
  });
});
