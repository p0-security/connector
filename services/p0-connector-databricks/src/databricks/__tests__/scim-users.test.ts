import { describe, expect, it, vi } from "vitest";

import {
  ACCOUNTS_URL,
  ACCOUNT_ID,
  type FetchMock,
  WORKSPACE_URL,
  accountContext,
  fetchCalls,
  isTokenExchange,
  jsonResponse,
  resetBetweenTests,
  stubFetch,
} from "../../__tests__/http.ts";
import { newDatabricksClient } from "../client.ts";
import {
  accountScimUsers,
  newScimUsers,
  workspaceScimUsers,
} from "../scim-users.ts";

vi.mock("@aws-sdk/client-sts", async (importOriginal) =>
  (await import("../../__tests__/sts.ts")).fakeStsModule(importOriginal)
);

resetBetweenTests();

const ALICE = {
  id: "1001",
  userName: "alice@example.com",
  emails: [{ value: "alice@example.com" }],
};
const BOB = {
  id: "1002",
  userName: "bob@example.com",
  emails: [{ value: "bob.alias@example.com" }],
};

/** Answers every account SCIM `Users` search with `users`, ignoring the filter, as a broken server might. */
const ignoringFilter = (users: unknown[]) =>
  stubFetch(() =>
    jsonResponse({ totalResults: users.length, Resources: users })
  );

const client = () => newDatabricksClient(accountContext());

/** Each endpoint, the Users URL it reads, and the name its errors use. */
const endpoints = [
  [
    "account SCIM",
    () => accountScimUsers(client()),
    `${ACCOUNTS_URL}/api/2.0/accounts/${ACCOUNT_ID}/scim/v2/Users`,
    "account SCIM Users",
  ],
  [
    "the workspace's SCIM proxy",
    () => workspaceScimUsers(client().inWorkspace(WORKSPACE_URL)),
    `${WORKSPACE_URL}/api/2.0/account/scim/v2/Users`,
    "account SCIM Users through the workspace",
  ],
] as const;

const searches = (fetchMock: FetchMock) =>
  fetchCalls(fetchMock).filter((call) => !isTokenExchange(call));

describe.each(endpoints)(
  "newScimUsers on %s",
  (_, endpoint, usersUrl, what) => {
    const scimUsers = () => newScimUsers(endpoint());

    it("searches Users there, escaping quotes and backslashes in the filter value", async () => {
      const fetchMock = ignoringFilter([]);

      await scimUsers().byEmail('a"b\\c@example.com');

      const calls = searches(fetchMock);
      expect(calls.map(({ url }) => url.split("?")[0])).toEqual([
        usersUrl,
        usersUrl,
      ]);
      expect(
        calls.map(({ url }) => new URL(url).searchParams.get("filter"))
      ).toEqual([
        'userName eq "a\\"b\\\\c@example.com"',
        'emails.value eq "a\\"b\\\\c@example.com"',
      ]);
    });

    it("re-checks results, so a server that ignored the filter can't hand back someone else", async () => {
      ignoringFilter([ALICE, BOB]);
      const users = scimUsers();

      await expect(users.byUserName("carol@example.com")).resolves.toBeNull();
      await expect(users.byEmail("carol@example.com")).resolves.toBeNull();
      await expect(users.byUserName("ALICE@example.com")).resolves.toEqual(
        ALICE
      );
      await expect(users.byEmail("bob.alias@example.com")).resolves.toEqual(
        BOB
      );
    });

    it("fails naming both users when two match", async () => {
      const robert = { ...BOB, id: "1003", userName: "robert@example.com" };
      ignoringFilter([BOB, robert]);

      await expect(
        scimUsers().byEmail("bob.alias@example.com")
      ).rejects.toMatchObject({
        message:
          "More than one Databricks user matches bob.alias@example.com: bob@example.com (1002), robert@example.com (1003)",
        data: { type: "validation_error" },
      });
    });

    it("reads a user by ID there", async () => {
      const fetchMock = stubFetch(() => jsonResponse(ALICE));

      await expect(scimUsers().byId(ALICE.id)).resolves.toEqual(ALICE);
      expect(searches(fetchMock).map(({ url }) => url)).toEqual([
        `${usersUrl}/${ALICE.id}`,
      ]);
    });

    it("returns null for an ID no user has (404)", async () => {
      stubFetch(() =>
        jsonResponse({ detail: "User not found" }, { status: 404 })
      );

      await expect(scimUsers().byId("3333")).resolves.toBeNull();
    });

    it("fails as itself on any other error reading by ID", async () => {
      stubFetch(() => jsonResponse({ detail: "try later" }, { status: 503 }));

      await expect(scimUsers().byId(ALICE.id)).rejects.toMatchObject({
        data: { type: "upstream_unavailable" },
      });
    });

    it("names the endpoint on a response it can't read", async () => {
      stubFetch(() => jsonResponse({ Resources: [{ userName: "no-id" }] }));

      await expect(
        scimUsers().byUserName("no-id@example.com")
      ).rejects.toMatchObject({
        message: `Databricks ${what} returned an unexpected response`,
        data: { type: "unknown" },
      });
    });
  }
);
