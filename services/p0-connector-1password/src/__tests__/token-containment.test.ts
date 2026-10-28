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
  AuthExpiredError,
  type FakeOnePassword,
  RateLimitExceededError,
  SHARING_POLICY,
  fakeItem,
  newFakeOnePassword,
} from "./fake-one-password.ts";
import {
  ALLOWED_PATTERN,
  AWS_SECRET,
  CREDENTIALS,
  EMAIL,
  ITEM,
  TOKEN,
  VAULT,
} from "./fixtures.ts";

/**
 * The service account token never leaves the connector. It is read from the
 * customer's secret manager and handed to the 1Password SDK's sign-in, and
 * to nothing else. It's never in a response P0 gets, an error or a log line,
 * however the SDK fails, even when the SDK's own message quotes it.
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
const sdk = vi.hoisted(() => ({ createClient: vi.fn() }));
const logged = vi.hoisted((): { lines: string[] } => ({ lines: [] }));

vi.mock("@p0security/secret-manager-client", async (importOriginal) => ({
  ...(await importOriginal<typeof secretManagerClient>()),
  createSecretManagerClient: vault.createSecretManagerClient,
}));

vi.mock("@1password/sdk", () => sdk);

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

const CONTEXT = { ...CREDENTIALS, requestId: "req-1" };

type Operation = {
  path: string;
  /** The tRPC client's method for it. */
  type: "mutate" | "query";
  input: unknown;
  /** Whether a working call reads the token and signs in to 1Password. */
  signsIn: boolean;
};

const operation =
  (type: Operation["type"]) =>
  (path: string, input: unknown, signsIn = false): Operation => ({
    path: `1password.${path}`,
    type,
    input,
    signsIn,
  });
const query = operation("query");
const mutation = operation("mutate");

const OPERATIONS: [string, Operation][] = [
  ["install validation", query("install.validation.get", CREDENTIALS, true)],
  [
    "share an item",
    mutation(
      "install.share.create",
      {
        ...CREDENTIALS,
        itemId: ITEM,
        email: EMAIL,
        expireAfter: "OneDay",
        oneTimeOnly: false,
      },
      true
    ),
  ],
  [
    "list items",
    query(
      "accesses.share.list",
      { query: { type: "items", context: CREDENTIALS } },
      true
    ),
  ],
  [
    "list vaults",
    query(
      "accesses.share.list",
      { query: { type: "vaults", context: { tokenSecret: AWS_SECRET } } },
      true
    ),
  ],
  [
    "read the sharing policy",
    query(
      "accesses.share.list",
      {
        query: {
          type: "sharing-policy",
          context: CREDENTIALS,
          itemId: ITEM,
        },
      },
      true
    ),
  ],
  [
    "provisionUser",
    mutation("accesses.share.provisionUser", {
      userBody: EMAIL,
      context: CONTEXT,
    }),
  ],
  [
    "setPoliciesForUser",
    mutation("accesses.share.setPoliciesForUser", {
      userId: EMAIL,
      policies: [{}],
      context: CONTEXT,
    }),
  ],
  [
    "deleteUser",
    mutation("accesses.share.deleteUser", { userId: EMAIL, context: CONTEXT }),
  ],
];

/** The SDK calls a scenario can fail. */
type SdkCall = "getAccountPolicy" | "getOverview" | "list" | "signIn";

type Scenario = {
  /** The SDK call to fail, and how. */
  sdkFailure?: { call: SdkCall; error: Error };
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
  /** Whether the call asked the secret manager for the token. */
  readToken: boolean;
  logs: string[];
  fake: FakeOnePassword;
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
  { sdkFailure, stored = TOKEN, vaultError }: Scenario,
  { path, type, input }: Operation
): Promise<Observed> => {
  logged.lines.length = 0;
  vault.createSecretManagerClient.mockResolvedValue({
    getSecretValue: vault.getSecretValue,
  });
  if (vaultError) vault.getSecretValue.mockRejectedValue(vaultError);
  else {
    // A new version of the secret each time, so each observation signs in
    // afresh.
    vault.getSecretValue.mockResolvedValue({
      value: stored,
      version: { ref: `op-token/versions/${++versions}` },
    });
  }

  const fake = newFakeOnePassword({
    vaults: new Map([[VAULT, "Engineering"]]),
    items: new Map([[VAULT, [fakeItem(ITEM, "Prod database")]]]),
    policy: SHARING_POLICY,
  });
  const failing = {
    getOverview: fake.client.vaults.getOverview,
    list: fake.client.items.list,
    getAccountPolicy: fake.client.items.shares.getAccountPolicy,
  };
  if (sdkFailure && sdkFailure.call !== "signIn") {
    failing[sdkFailure.call].mockRejectedValue(sdkFailure.error);
  }
  sdk.createClient.mockImplementation(async () => {
    if (sdkFailure?.call === "signIn") throw sdkFailure.error;
    return fake.asClient();
  });

  const fromP0 = await settle(() => invoke(p0, `${path}.${type}`, input));
  const inProcess = await settle(() => invoke(connector, path, input));
  return {
    outputs: [fromP0, inProcess].flatMap(({ result, error }) =>
      renderings(error ?? result)
    ),
    p0Error: fromP0.error,
    readToken: vault.getSecretValue.mock.calls.length > 0,
    logs: [...logged.lines],
    fake,
  };
};

/** One line per text that holds the token, or its body. */
const leaks = (texts: string[], stored: string) => {
  const secrets = [TOKEN, TOKEN.slice("ops_".length), stored.trim()].filter(
    (secret) => secret !== ""
  );
  return texts.flatMap((text) =>
    secrets.some((secret) => text.includes(secret))
      ? [`the token, in: ${text.slice(0, 200)}`]
      : []
  );
};

const expectTokenContained = (
  { outputs, logs }: Observed,
  stored: string = TOKEN
) => {
  expect(leaks(outputs, stored)).toEqual([]);
  expect(leaks(logs, stored)).toEqual([]);
};

/** {@link observe}, then checks the token went nowhere but the SDK's sign-in. */
const sweep = async (scenario: Scenario, operation: Operation) => {
  const observed = await observe(scenario, operation);
  // A call that never reads the token proves nothing about it.
  expect(observed.readToken).toBe(operation.signsIn);
  const stored = scenario.stored?.toString("utf8") ?? TOKEN;
  expectTokenContained(observed, stored);
  for (const [config] of sdk.createClient.mock.calls) {
    expect(config).toMatchObject({ auth: stored.trim() });
  }
  return observed;
};

beforeEach(() => {
  vi.clearAllMocks();
});

describe("a working install", () => {
  it.each(OPERATIONS)(
    "%s keeps the token in the connector",
    async (_name, operation) => {
      const observed = await sweep({}, operation);

      // Otherwise no credential was in play, and this proves nothing.
      expect(sdk.createClient.mock.calls.length > 0).toBe(operation.signsIn);
      // Nor if the connector's log lines weren't the ones checked.
      expect(observed.logs).not.toEqual([]);
    }
  );
});

// The SDK quoting the token back, as its Rust core's message might.
const quoting = (kind: new (message: string) => Error) =>
  new kind(`rejected the service account token ${TOKEN}`);

const SDK_FAILURES: [string, Error][] = [
  ["a bare error", new Error("failed")],
  ["a bare error quoting the token", quoting(Error)],
  ["a rate limit quoting the token", quoting(RateLimitExceededError)],
  ["an expired token quoting the token", quoting(AuthExpiredError)],
  [
    "an error caused by one quoting the token",
    new Error("failed", { cause: quoting(Error) }),
  ],
];

const SDK_CALLS: SdkCall[] = [
  "signIn",
  "getOverview",
  "list",
  "getAccountPolicy",
];

describe.each(
  SDK_CALLS.flatMap((call) =>
    SDK_FAILURES.map(([failure, error]) => [failure, call, error] as const)
  )
)("the SDK failing with %s at %s", (_failure, call, error) => {
  it.each(OPERATIONS)("%s", async (_name, operation) => {
    await sweep({ sdkFailure: { call, error } }, operation);
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
    new SecretNotFoundError("op-token" as SecretRef, {
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

describe.each(VAULT_FAILURES)(
  "a secret manager that %s",
  (_case, vaultError) => {
    it.each(OPERATIONS)("%s", async (_name, operation) => {
      await sweep({ vaultError }, operation);

      // Without the token there's nothing to sign in with.
      expect(sdk.createClient).not.toHaveBeenCalled();
    });
  }
);

const STORED_SECRETS: [string, Buffer | string][] = [
  ["holds the token with a trailing newline", `${TOKEN}\n`],
  ["holds the token as a binary secret", Buffer.from(TOKEN, "utf8")],
  // What the AWS console's key/value editor stores. 1Password refuses it.
  [
    "holds the token as a JSON key/value pair",
    JSON.stringify({ token: TOKEN }),
  ],
];

describe.each(STORED_SECRETS)("a secret that %s", (_case, stored) => {
  it.each(OPERATIONS)("%s", async (_name, operation) => {
    await sweep({ stored }, operation);
  });
});

describe("the token where the pointer goes", () => {
  it("is refused as the pointer, without being repeated", async () => {
    const observed = await observe(
      {},
      query("install.validation.get", { ...CREDENTIALS, tokenSecret: TOKEN })
    );

    expect(observed.p0Error).toMatchObject({ data: { code: "BAD_REQUEST" } });
    expect(vault.getSecretValue).not.toHaveBeenCalled();
    expectTokenContained(observed);
  });
});
