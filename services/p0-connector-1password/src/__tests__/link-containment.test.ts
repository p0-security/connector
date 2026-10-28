import {
  createLogger,
  newCloudFunctionLink,
  newTRPCConnectorClient,
} from "@p0security/connector";
import { format, inspect } from "node:util";
import type * as pinoModule from "pino";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { connectorRouter, t } from "../router.ts";
import {
  FIELD_VALUE,
  type FakeOnePassword,
  LINK,
  RateLimitExceededError,
  SHARING_POLICY,
  fakeItem,
  newFakeOnePassword,
} from "./fake-one-password.ts";
import {
  ALLOWED_PATTERN,
  CREDENTIALS,
  EMAIL,
  ITEM,
  TOKEN,
  VAULT,
} from "./fixtures.ts";

/**
 * The share link goes to P0 in the share route's answer, and nowhere else:
 * not into a log line, and not into an error. The item's field values, which
 * the SDK returns with the item the link is made from, go nowhere at all.
 *
 * The route is driven through the real router twice: from P0's side, through
 * the Lambda handler, and in-process, for the error the router throws with
 * its whole cause chain.
 */

// `vi.hoisted` guarantees these exist before the (hoisted) `vi.mock` factories run.
const getServiceAccountToken = vi.hoisted(() => vi.fn());
const sdk = vi.hoisted(() => ({ createClient: vi.fn() }));
const logged = vi.hoisted((): { lines: string[] } => ({ lines: [] }));

vi.mock("../secrets.ts", () => ({ getServiceAccountToken }));
vi.mock("@1password/sdk", () => sdk);

// Every logger writes here instead of stdout, at every level.
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

vi.stubEnv("DOMAIN_ALLOW_PATTERN", ALLOWED_PATTERN);
const { handler } = await import("../index.ts");

const INPUT = {
  ...CREDENTIALS,
  itemId: ITEM,
  email: EMAIL,
  expireAfter: "OneDay" as const,
  oneTimeOnly: true,
};

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
  return [
    inspect(value, { depth: null, showHidden: true }),
    asJson(value),
    ...(value instanceof Error
      ? [String(value.stack), ...renderings(value.cause, depth + 1)]
      : []),
  ];
};

const settle = async (run: () => Promise<unknown>) => {
  try {
    return { result: await run() };
  } catch (error) {
    return { error };
  }
};

let fake: FakeOnePassword;
let versions = 0;

const observe = async () => {
  logged.lines.length = 0;
  const fromP0 = await settle(() =>
    p0["1password"].install.share.create.mutate(INPUT)
  );
  const inProcess = await settle(() =>
    connector["1password"].install.share.create(INPUT)
  );
  return {
    results: [fromP0.result, inProcess.result],
    errors: [fromP0.error, inProcess.error].flatMap((error) =>
      renderings(error)
    ),
    logs: [...logged.lines],
  };
};

const containing = (texts: string[], secret: string) =>
  texts
    .filter((text) => text.includes(secret))
    .map((text) => text.slice(0, 200));

beforeEach(() => {
  vi.clearAllMocks();
  getServiceAccountToken.mockImplementation(async () => ({
    token: TOKEN,
    version: `op-token/versions/${++versions}`,
  }));
  fake = newFakeOnePassword({
    vaults: new Map([[VAULT, "Engineering"]]),
    items: new Map([[VAULT, [fakeItem(ITEM, "Prod database")]]]),
    policy: SHARING_POLICY,
  });
  sdk.createClient.mockImplementation(async () => fake.asClient());
});

describe("a share that works", () => {
  it("answers with the link, and logs neither it nor a field's value", async () => {
    const { results, errors, logs } = await observe();

    expect(results).toEqual([
      { link: LINK, expiresAt: expect.any(String), oneTimeOnly: true },
      { link: LINK, expiresAt: expect.any(String), oneTimeOnly: true },
    ]);
    expect(errors).toEqual([]);
    // Otherwise the log lines checked weren't the connector's.
    expect(logs.some((line) => line.includes("shared the item"))).toBe(true);
    expect(containing(logs, LINK)).toEqual([]);
    expect(containing(logs, FIELD_VALUE)).toEqual([]);
    expect(containing(logs, TOKEN)).toEqual([]);
  });
});

// The SDK quoting what it was handed: the item's field value, or the link.
const quoting = (kind: new (message: string) => Error) =>
  new kind(`failed on ${FIELD_VALUE} for ${LINK}`);

const FAILURES = [
  ["getAccountPolicy", quoting(Error)],
  ["validateRecipients", quoting(Error)],
  ["create", quoting(Error)],
  ["create", quoting(RateLimitExceededError)],
  ["create", new Error("failed", { cause: quoting(Error) })],
] as const;

describe.each(FAILURES)("the SDK failing at %s", (call, error) => {
  it("fails without repeating the link or a field's value", async () => {
    fake.client.items.shares[call].mockRejectedValue(error);

    const { results, errors, logs } = await observe();

    expect(results).toEqual([undefined, undefined]);
    expect(errors).not.toEqual([]);
    for (const secret of [LINK, FIELD_VALUE, TOKEN]) {
      expect(containing(errors, secret)).toEqual([]);
      expect(containing(logs, secret)).toEqual([]);
    }
  });
});

describe("a share P0 sends outside the contract", () => {
  it.each([
    ["an expiry 1Password doesn't offer", { expireAfter: "TwoDays" }],
    ["a vault ID that isn't one", { vault: "engineering" }],
    ["no email", { email: undefined }],
  ])("refuses %s before reading the token", async (_case, override) => {
    const outcome = await settle(() =>
      connector["1password"].install.share.create({
        ...INPUT,
        ...override,
      } as never)
    );

    expect(outcome.error).toMatchObject({ code: "BAD_REQUEST" });
    expect(getServiceAccountToken).not.toHaveBeenCalled();
  });
});
