import { createLogger } from "@p0security/connector";
import { inspect } from "node:util";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { connectorRouter } from "../router.ts";
import { type FakeAccount, databricks, fakeAccount } from "./databricks.ts";
import {
  SP_SCIM_ID,
  WORKSPACE_ID,
  accountContext,
  fetchCalls,
  isTokenExchange,
  resetBetweenTests,
  stubFetch,
} from "./http.ts";
import { logLines } from "./logs.ts";

vi.mock("@aws-sdk/client-sts", async (importOriginal) =>
  (await import("./sts.ts")).fakeStsModule(importOriginal)
);

vi.mock("@p0security/connector", async (importOriginal) =>
  (await import("./logs.ts")).recordingLoggerModule(importOriginal)
);

resetBetweenTests();

/** What `stubFetch` issues as every Databricks token. */
const TOKEN = "dbx-token-";

let account: FakeAccount;

beforeEach(() => {
  logLines.length = 0;
  account = fakeAccount();
  account.metastores = [
    { metastore_id: "m-1", name: "main", owner: "metastore-admins" },
  ];
  account.groups = [
    { id: "3001", displayName: "metastore-admins", members: [SP_SCIM_ID] },
  ];
});

const validation = () =>
  connectorRouter.createCaller({ logger: createLogger() })["databricks-ai"]
    .install.validation;

const everyCheck = () =>
  validation().get({
    ...accountContext(),
    requireAccountAdmin: true,
    requireMetastoreAdmin: true,
    ownerPrincipal: "metastore-admins",
  });

const probe = () =>
  validation().probe({ ...accountContext(), workspaceId: WORKSPACE_ID });

/** Runs `call` and returns what it resolved or rejected with. */
const settle = async (call: () => Promise<unknown>) => {
  try {
    return { result: await call() };
  } catch (error) {
    return { error };
  }
};

/** Each route on a passing path and on each kind of failure. */
const runs: [string, (a: FakeAccount) => void, () => Promise<unknown>][] = [
  ["get, passing", () => {}, everyCheck],
  [
    "get, refused with a 403",
    (a) => {
      a.refuse["GET /metastores"] = 403;
    },
    everyCheck,
  ],
  [
    "get, failing a check",
    (a) => {
      a.metastores = [{ metastore_id: "m-1", name: "main" }];
    },
    everyCheck,
  ],
  [
    "get, with Databricks down",
    (a) => {
      a.refuse[`GET /scim/v2/ServicePrincipals`] = 503;
    },
    everyCheck,
  ],
  ["probe, passing", () => {}, probe],
  [
    "probe, with the beta off",
    (a) => {
      a.mcp = [{ status: 404 }];
    },
    probe,
  ],
  [
    "probe, with the gateway down",
    (a) => {
      a.mcp = [{ status: 502 }];
    },
    probe,
  ],
  [
    "probe, refused with a 403",
    (a) => {
      a.refuse[`GET /workspaces/${WORKSPACE_ID}/permissionassignments`] = 403;
    },
    probe,
  ],
];

describe("the Databricks token", () => {
  it.each(runs)(
    "only ever travels in an Authorization header: %s",
    async (_, setUp, call) => {
      setUp(account);
      const fetchMock = stubFetch(databricks(account));

      const outcome = await settle(call);

      const calls = fetchCalls(fetchMock).filter((c) => !isTokenExchange(c));
      expect(calls.length).toBeGreaterThan(0);
      for (const { url, init } of calls) {
        const { Authorization, ...headers } = init.headers;
        expect(Authorization).toMatch(new RegExp(`^Bearer ${TOKEN}\\d+$`));
        expect(url).not.toContain(TOKEN);
        expect(JSON.stringify(headers)).not.toContain(TOKEN);
        expect(init.body ?? "").not.toContain(TOKEN);
      }
      expect(inspect(outcome, { depth: null })).not.toContain(TOKEN);
      expect(logLines.length).toBeGreaterThan(0);
      expect(logLines.filter((line) => line.includes(TOKEN))).toEqual([]);
    }
  );
});
