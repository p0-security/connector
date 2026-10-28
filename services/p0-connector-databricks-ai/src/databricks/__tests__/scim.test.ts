import { describe, expect, it, vi } from "vitest";

import {
  ACCOUNT_API,
  ACCOUNT_ID,
  APPLICATION_ID,
  accountContext,
  databricksCalls,
  jsonResponse,
  resetBetweenTests,
  stubFetch,
} from "../../__tests__/http.ts";
import { newDatabricksClient } from "../client.ts";
import { newAccountScim } from "../scim.ts";

vi.mock("@aws-sdk/client-sts", async (importOriginal) =>
  (await import("../../__tests__/sts.ts")).fakeStsModule(importOriginal)
);

resetBetweenTests();

const scim = () => newAccountScim(newDatabricksClient(accountContext()));

/** Answers every account SCIM search with `resources`, ignoring the filter, as a broken server might. */
const ignoringFilter = (resources: unknown[]) =>
  stubFetch(() =>
    jsonResponse({ totalResults: resources.length, Resources: resources })
  );

const OTHER_APP_ID = "00000000-0000-4000-8000-000000000000";

/** Each lookup by filter: the endpoint, the filtered attribute, a match, and a near miss. */
const lookups = [
  [
    "userByUserName",
    "Users",
    "userName",
    { id: "1001", userName: "Alice@Example.com" },
    { id: "1002", userName: "bob@example.com" },
  ],
  [
    "servicePrincipalByApplicationId",
    "ServicePrincipals",
    "applicationId",
    { id: "2001", applicationId: APPLICATION_ID },
    { id: "2002", applicationId: OTHER_APP_ID },
  ],
  [
    "servicePrincipalByDisplayName",
    "ServicePrincipals",
    "displayName",
    { id: "2001", applicationId: APPLICATION_ID, displayName: "p0-agent-r1" },
    { id: "2002", applicationId: OTHER_APP_ID, displayName: "p0-agent-r10" },
  ],
  [
    "groupByDisplayName",
    "Groups",
    "displayName",
    { id: "3001", displayName: "data-owners" },
    { id: "3002", displayName: "data-owners-ro" },
  ],
] as const;

/** The value each match is looked up by. */
const valueOf = (match: Record<string, string>, attribute: string) =>
  match[attribute]!;

describe("newAccountScim", () => {
  describe.each(lookups)("%s", (lookup, resource, attribute, match, miss) => {
    it("searches account SCIM, escaping quotes and backslashes in the filter value", async () => {
      const fetchMock = ignoringFilter([]);

      await scim()[lookup]('a"b\\c');

      const [call] = databricksCalls(fetchMock);
      const url = new URL(call?.url ?? "");
      expect(`${url.origin}${url.pathname}`).toBe(
        `${ACCOUNT_API}/scim/v2/${resource}`
      );
      expect(url.searchParams.get("filter")).toBe(
        `${attribute} eq "a\\"b\\\\c"`
      );
    });

    it("returns the one result that matches, ignoring case, and drops any the filter shouldn't have returned", async () => {
      ignoringFilter([miss, match]);

      await expect(
        scim()[lookup](valueOf(match, attribute).toUpperCase())
      ).resolves.toEqual(match);
    });

    it("returns null when nothing matches", async () => {
      ignoringFilter([miss]);

      await expect(
        scim()[lookup](valueOf(match, attribute))
      ).resolves.toBeNull();
    });

    it("refuses two matches, naming both", async () => {
      ignoringFilter([match, { ...match, id: "9999" }]);

      await expect(
        scim()[lookup](valueOf(match, attribute))
      ).rejects.toMatchObject({
        message: expect.stringContaining(`${match.id}, 9999`),
        data: { type: "validation_error" },
      });
    });

    it("says P0's principal isn't an account admin when account SCIM answers 403", async () => {
      stubFetch(() =>
        jsonResponse(
          { error_code: "PERMISSION_DENIED", message: "refused" },
          { status: 403 }
        )
      );

      await expect(
        scim()[lookup](valueOf(match, attribute))
      ).rejects.toMatchObject({
        message: expect.stringContaining(
          `is not an account admin in Databricks account ${ACCOUNT_ID}`
        ),
        data: { type: "insufficient_privileges" },
      });
    });
  });

  describe("by account SCIM ID", () => {
    it("reads a group with its direct members", async () => {
      const fetchMock = stubFetch(() =>
        jsonResponse({
          id: "3001",
          displayName: "data-owners",
          members: [{ value: "1001", display: "alice" }],
        })
      );

      await expect(scim().groupById("3001")).resolves.toEqual({
        id: "3001",
        displayName: "data-owners",
        members: [{ value: "1001" }],
      });
      expect(databricksCalls(fetchMock).map(({ url }) => url)).toEqual([
        `${ACCOUNT_API}/scim/v2/Groups/3001`,
      ]);
    });

    it("reads a service principal", async () => {
      const fetchMock = stubFetch(() =>
        jsonResponse({ id: "2001", applicationId: APPLICATION_ID })
      );

      await expect(scim().servicePrincipalById("2001")).resolves.toEqual({
        id: "2001",
        applicationId: APPLICATION_ID,
      });
      expect(databricksCalls(fetchMock).map(({ url }) => url)).toEqual([
        `${ACCOUNT_API}/scim/v2/ServicePrincipals/2001`,
      ]);
    });

    it.each(["groupById", "servicePrincipalById"] as const)(
      "%s returns null for an ID account SCIM doesn't know",
      async (lookup) => {
        stubFetch(() =>
          jsonResponse(
            { detail: "not found", status: "404" },
            { status: 404, statusText: "Not Found" }
          )
        );

        await expect(scim()[lookup]("4040")).resolves.toBeNull();
      }
    );
  });
});
