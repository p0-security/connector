// copy of services/p0-connector-harbor/src/__tests__/fixtures.ts, with Argo CD's
// API token in place of Harbor's robot account
/** The values and helpers the connector's tests share. */
import { ConnectorError, createLogger } from "@p0security/connector";
import { inspect } from "node:util";
import { vi } from "vitest";

/** Stands in for the connector's API token, with a marker a leak check can search for. */
export const TOKEN = "SENTINEL-argocd-token-3e81b2";

// Every field of a pointer has a value of its own, so a leak check can tell
// which one got out.
export const AWS_SECRET = {
  manager: "aws" as const,
  region: "sentinel-region-9d2c",
  secretId: "sentinel-secret-id-51fa",
};

export const GCP_SECRET = {
  manager: "gcp" as const,
  projectId: "sentinel-project-4b7e",
  secretId: "sentinel-secret-id-51fa",
};

export const ARGOCD_HOST = "argocd.example.com";

/** An instance as P0 sends it, with the namespace left to its default. */
export const INSTANCE = {
  url: `https://${ARGOCD_HOST}`,
  managingApp: "platform/argocd",
  secret: AWS_SECRET,
};

/**
 * What must reach no error and no log line: the token, by a prefix short
 * enough to catch a truncated copy, and each field of a pointer but its
 * manager.
 */
export const NEVER_SHOWN = [
  TOKEN.slice(0, 12),
  AWS_SECRET.secretId,
  AWS_SECRET.region,
  GCP_SECRET.projectId,
];

/** The one logger the tests pass around. It prints nothing. */
export const logger = createLogger();
logger.level = "silent";

/**
 * Records everything logged through {@link logger}: each line, and what each
 * child logger was bound to, since a binding is printed on every line of the
 * child. Returns a function that renders all of it, with anything else it is
 * given, as one string to search.
 */
export const recordLogger = () => {
  // Every child logs through the one logger.
  const child = vi.spyOn(logger, "child").mockReturnValue(logger);
  const lines = [
    vi.spyOn(logger, "debug"),
    vi.spyOn(logger, "info"),
    vi.spyOn(logger, "warn"),
    vi.spyOn(logger, "error"),
  ];
  return {
    lines: () => lines.flatMap((line) => line.mock.calls),
    seen: (...others: unknown[]) =>
      inspect(
        [others, child.mock.calls, lines.map((line) => line.mock.calls)],
        { depth: null }
      ),
  };
};

/** The `ConnectorError` `run` fails with. Anything else it throws, or no failure at all, fails the test. */
export const connectorError = async (run: () => Promise<unknown>) => {
  try {
    await run();
  } catch (error) {
    if (error instanceof ConnectorError) return error;
    throw error;
  }
  throw new Error("expected the call to throw");
};

/**
 * A seeded source of random numbers in [0, 1) (mulberry32), for property
 * tests: a failing case comes back with the same seed.
 */
export const seededRandom = (seed: number) => {
  let state = seed >>> 0;
  return () => {
    state = (state + 0x6d2b79f5) >>> 0;
    let t = state;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
};

/** The seed a property test runs with: `PROPERTY_SEED`, or a new one. */
export const propertySeed = () => {
  const given = process.env.PROPERTY_SEED;
  if (!given) return Math.floor(Math.random() * 2 ** 32);
  const seed = Number(given);
  if (!Number.isSafeInteger(seed)) {
    throw new Error(`PROPERTY_SEED isn't an integer: ${given}`);
  }
  return seed;
};
