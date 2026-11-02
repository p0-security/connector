/** The values and helpers the connector's tests share. */
import { ConnectorError, createLogger } from "@p0security/connector-core";
import { inspect } from "node:util";
import { afterEach, beforeEach, vi } from "vitest";

import { readToken } from "../secrets.ts";

/** The access token the secret holds. A marker a leak check can find. */
export const TOKEN = "eyJtaXJvLlNFTlRJTkVMIn0_token-7f3a0c9e";

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

/**
 * The team's id, as `GET /v1/oauth-token` reports it. Above 2^53, as Miro's
 * ids are, so a rounded read shows.
 */
export const TEAM_ID = "3458764688635236553";

/** The connector user's id, also above 2^53. */
export const USER_ID = "3458764688747789111";

/** Where Miro's REST API lives. */
export const API = "https://api.miro.com";

export const INSTALL_INPUT = { secret: AWS_SECRET };

/**
 * Before each test: clears the mocks, and has the secret answer
 * {@link TOKEN}. After each test: undoes every mock and stub. The test file
 * mocks `secrets.ts` itself, since `vi.mock` is hoisted per file.
 */
export const stubToken = () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(readToken).mockResolvedValue(TOKEN);
  });

  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
  });
};

/**
 * What must reach no error and no log line: the token, and each field of a
 * pointer but its manager.
 */
export const NEVER_SHOWN = [
  TOKEN,
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
