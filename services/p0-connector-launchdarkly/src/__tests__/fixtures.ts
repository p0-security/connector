/** The values and helpers the connector's tests share. */
import { ConnectorError, createLogger } from "@p0security/connector";
import { inspect } from "node:util";
import { afterEach, beforeEach, vi } from "vitest";

import type { BaseRequestContext } from "../accesses/common/definition.ts";
import type { Pause } from "../accesses/common/policies.ts";
import { DOMAIN_ALLOW_PATTERN_ENV } from "../allowlist.ts";
import type {
  FakeLaunchDarklyState,
  FakeMember,
} from "../launchdarkly/__tests__/fake-launchdarkly.ts";
import { LaunchDarklyError } from "../launchdarkly/api.ts";
import { readToken } from "../secrets.ts";

/** The access token the secret holds. A marker a leak check can find. */
export const TOKEN = "api-SENTINEL-token-7f3a0c9e";

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

/** The account's id, as `GET /caller-identity` reports it. */
export const ACCOUNT_ID = "5f3c2b1a0e9d8c7b6a5f4e3d";

/** Another LaunchDarkly account's id, for a token moved to the wrong secret. */
export const OTHER_ACCOUNT_ID = "6f3c2b1a0e9d8c7b6a5f4e3d";

/** The member a personal token acts as. */
export const TOKEN_OWNER_ID = "60a1b2c3d4e5f60718293a4b";

/** The commercial instance's host. */
export const LAUNCHDARKLY_HOST = "app.launchdarkly.com";

/** Where the commercial instance's REST API lives. */
export const API = `https://${LAUNCHDARKLY_HOST}/api/v2`;

/** The member the tests act on. */
export const MEMBER_ID = "507f1f77bcf86cd799439011";

/** The member's own route. */
export const MEMBER = `${API}/members/${MEMBER_ID}`;

/** A custom role's `_id`. */
export const ROLE_ID = "1234a56b7c89d012345e678f";

export const ACCOUNT = {
  instance: "commercial" as const,
  accountId: ACCOUNT_ID,
  secret: AWS_SECRET,
};

/** The user body P0 sends for {@link MEMBER_ID}. */
export const USER_BODY = { accountId: ACCOUNT_ID, memberId: MEMBER_ID };

export const INSTALL_INPUT = {
  instance: "commercial" as const,
  secret: AWS_SECRET,
};

/** An email P0 holds for a principal. A marker a leak check can find. */
export const EMAIL = "sentinel-person@example.com";

/** The connector's `DOMAIN_ALLOW_PATTERN`, which allows {@link EMAIL}. */
export const PATTERN = "example\\.com";

/** A grant's request context on {@link ACCOUNT}, for {@link EMAIL}. */
export const baseContext = (
  overrides: Partial<BaseRequestContext> = {}
): BaseRequestContext => ({
  ...ACCOUNT,
  requestId: "req-1",
  email: EMAIL,
  operation: "grant",
  ...overrides,
});

/** A pause that doesn't wait. */
export const noPause: Pause = async () => {};

/** The fake's one member. */
export const memberOf = (launchDarkly: {
  state: FakeLaunchDarklyState;
}): FakeMember => {
  const member = launchDarkly.state.members?.[0];
  if (member === undefined) throw new Error("the fake has no member");
  return member;
};

/** Each write the fake got, by its call and body. */
export const writes = (launchDarkly: {
  writes: () => { body: unknown; call: string }[];
}) => launchDarkly.writes().map(({ call, body }) => ({ call, body }));

/**
 * Before each test: clears the mocks, sets the domain pattern to
 * {@link PATTERN}, and has the secret answer {@link TOKEN}. After each test:
 * undoes every mock and stub. The test file mocks `secrets.ts` itself, since
 * `vi.mock` is hoisted per file.
 */
export const stubPatternAndToken = () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.stubEnv(DOMAIN_ALLOW_PATTERN_ENV, PATTERN);
    vi.mocked(readToken).mockResolvedValue(TOKEN);
  });

  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
    vi.unstubAllEnvs();
  });
};

/**
 * What must reach no error and no log line: the token, the principal's
 * email, and each field of a pointer but its manager.
 */
export const NEVER_SHOWN = [
  TOKEN,
  EMAIL,
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

/** The {@link LaunchDarklyError} `run` fails with. Anything else fails the test. */
export const launchDarklyError = async (run: () => Promise<unknown>) => {
  const outcome = await run().then(
    () => new Error("expected the call to throw"),
    (error: unknown) => error
  );
  if (outcome instanceof LaunchDarklyError) return outcome;
  throw outcome;
};
