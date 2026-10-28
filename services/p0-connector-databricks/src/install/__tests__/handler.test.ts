import { createLogger } from "@p0security/connector";
import { beforeEach, describe, expect, it, vi } from "vitest";

import {
  ACCOUNTS_URL,
  ACCOUNT_ID,
  APPLICATION_ID,
  METASTORE_ASSIGNMENT,
  METASTORE_ID,
  SP_SCIM_ID,
  WORKSPACE_ID,
  WORKSPACE_URL,
  accountContext,
  bindingResponse,
  fetchCalls,
  isBinding,
  isTokenExchange,
  jsonResponse,
  resetBetweenTests,
  stubFetch,
} from "../../__tests__/http.ts";
import { DOMAIN_PATTERN_ENV } from "../../domain.ts";
import { connectorRouter } from "../../router.ts";
import type { InstallValidationInput } from "../definition.ts";

vi.mock("@aws-sdk/client-sts", async (importOriginal) =>
  (await import("../../__tests__/sts.ts")).fakeStsModule(importOriginal)
);

resetBetweenTests();

const servicePrincipal = {
  id: SP_SCIM_ID,
  applicationId: APPLICATION_ID,
  displayName: "p0-connector",
};

const ADMINS = { display: "admins", value: "100" };
const USERS = { display: "users", value: "101" };

/** What Databricks answers, set per test. */
let roles: { value: string }[];
let groups: { display?: string; value: string }[] | undefined;
let servicePrincipalStatus: number;
let meStatus: number;
let bindingWorkspaceId: string;

/**
 * Answers account SCIM, workspace /Me and the workspace's metastore
 * assignment the way Databricks would for the connector's principal.
 */
const databricks = (url: string) => {
  const { pathname } = new URL(url);
  const refused = (status: number) =>
    jsonResponse(
      { error_code: "PERMISSION_DENIED", message: "refused" },
      { status }
    );
  if (pathname.endsWith("/scim/v2/ServicePrincipals")) {
    return jsonResponse({ totalResults: 1, Resources: [servicePrincipal] });
  }
  if (pathname.endsWith(`/scim/v2/ServicePrincipals/${SP_SCIM_ID}`)) {
    return servicePrincipalStatus === 200
      ? jsonResponse({ ...servicePrincipal, roles })
      : refused(servicePrincipalStatus);
  }
  if (url === `${WORKSPACE_URL}/api/2.0/preview/scim/v2/Me`) {
    return meStatus === 200
      ? jsonResponse({ id: SP_SCIM_ID, userName: APPLICATION_ID, groups })
      : refused(meStatus);
  }
  if (isBinding(url)) return bindingResponse(bindingWorkspaceId);
  return jsonResponse(
    { error_code: "RESOURCE_DOES_NOT_EXIST", message: "not found" },
    { status: 404 }
  );
};

const databricksCalls = (fetchMock: ReturnType<typeof stubFetch>) =>
  fetchCalls(fetchMock).filter((c) => !isTokenExchange(c));

// Calling through the connector router also proves the `databricks`
// namespace is registered with its install router.
const validate = (input: InstallValidationInput) =>
  connectorRouter
    .createCaller({ logger: createLogger() })
    .databricks.install.validation.get(input);

const withWorkspace = (overrides: Partial<InstallValidationInput> = {}) => ({
  ...accountContext(),
  workspaceId: WORKSPACE_ID,
  workspaceUrl: WORKSPACE_URL,
  ...overrides,
});

const notAccountAdmin = {
  message: `Service principal ${APPLICATION_ID} is not an account admin in Databricks account ${ACCOUNT_ID}`,
  data: { type: "insufficient_privileges" },
};

beforeEach(() => {
  vi.stubEnv(DOMAIN_PATTERN_ENV, "example\\.com");
  roles = [{ value: "account_admin" }];
  groups = [USERS];
  servicePrincipalStatus = 200;
  meStatus = 200;
  bindingWorkspaceId = WORKSPACE_ID;
});

describe("install validation", () => {
  describe("for an account", () => {
    it("only exchanges a token, calling no Databricks API", async () => {
      const fetchMock = stubFetch(databricks);

      await expect(validate(accountContext())).resolves.toEqual({
        servicePrincipal: null,
        workspace: null,
      });

      const calls = fetchCalls(fetchMock);
      expect(calls).toHaveLength(1);
      expect(calls[0]?.url).toBe(
        `${ACCOUNTS_URL}/oidc/accounts/${ACCOUNT_ID}/v1/token`
      );
    });

    it("fails when the token exchange is refused", async () => {
      vi.stubGlobal(
        "fetch",
        vi.fn(async () =>
          jsonResponse(
            { error: "invalid_request", error_description: "no policy" },
            { status: 401 }
          )
        )
      );

      await expect(validate(accountContext())).rejects.toMatchObject({
        data: { type: "insufficient_privileges" },
      });
    });
  });

  describe("with requireAccountAdmin", () => {
    it("finds the service principal in account SCIM and checks its roles", async () => {
      const fetchMock = stubFetch(databricks);

      await expect(
        validate({ ...accountContext(), requireAccountAdmin: true })
      ).resolves.toEqual({ servicePrincipal, workspace: null });

      expect(databricksCalls(fetchMock).map((c) => c.url)).toEqual([
        `${ACCOUNTS_URL}/api/2.0/accounts/${ACCOUNT_ID}/scim/v2/ServicePrincipals?${new URLSearchParams(
          { filter: `applicationId eq "${APPLICATION_ID}"` }
        ).toString()}`,
        `${ACCOUNTS_URL}/api/2.0/accounts/${ACCOUNT_ID}/scim/v2/ServicePrincipals/${SP_SCIM_ID}`,
      ]);
    });

    it("refuses a principal without account_admin", async () => {
      roles = [];
      stubFetch(databricks);

      await expect(
        validate({ ...accountContext(), requireAccountAdmin: true })
      ).rejects.toMatchObject(notAccountAdmin);
    });

    it("gives the same refusal when account SCIM answers the lookup with a 403", async () => {
      stubFetch((url) =>
        new URL(url).pathname.endsWith("/scim/v2/ServicePrincipals")
          ? jsonResponse(
              { error_code: "PERMISSION_DENIED", message: "refused" },
              { status: 403 }
            )
          : databricks(url)
      );

      await expect(
        validate({ ...accountContext(), requireAccountAdmin: true })
      ).rejects.toMatchObject(notAccountAdmin);
    });

    it("gives the same refusal when account SCIM answers the fresh read with a 403", async () => {
      servicePrincipalStatus = 403;
      stubFetch(databricks);

      await expect(
        validate({ ...accountContext(), requireAccountAdmin: true })
      ).rejects.toMatchObject(notAccountAdmin);
    });

    it("reads the roles fresh on every validation", async () => {
      roles = [];
      stubFetch(databricks);
      await expect(
        validate({ ...accountContext(), requireAccountAdmin: true })
      ).rejects.toThrow();

      roles = [{ value: "account_admin" }];
      await expect(
        validate({ ...accountContext(), requireAccountAdmin: true })
      ).resolves.toMatchObject({ servicePrincipal });
    });

    it("fails when account SCIM doesn't know the principal", async () => {
      stubFetch(() => jsonResponse({ totalResults: 0 }));

      await expect(
        validate({ ...accountContext(), requireAccountAdmin: true })
      ).rejects.toMatchObject({ data: { type: "object_not_found" } });
    });
  });

  describe("for a workspace", () => {
    it("calls SCIM /Me, then binds the URL, and reports what it found", async () => {
      const fetchMock = stubFetch(databricks);

      await expect(validate(withWorkspace())).resolves.toEqual({
        servicePrincipal: null,
        workspace: {
          identity: { id: SP_SCIM_ID, userName: APPLICATION_ID, groups },
          metastoreId: METASTORE_ID,
          isAdmin: false,
        },
      });

      expect(databricksCalls(fetchMock).map((c) => c.url)).toEqual([
        `${WORKSPACE_URL}/api/2.0/preview/scim/v2/Me`,
        `${WORKSPACE_URL}${METASTORE_ASSIGNMENT}`,
      ]);
    });

    it("reports a principal in the admins group as an admin", async () => {
      groups = [USERS, ADMINS];
      stubFetch(databricks);

      await expect(validate(withWorkspace())).resolves.toMatchObject({
        workspace: { isAdmin: true },
      });
    });

    it.each([401, 403])(
      "says the principal can't call the workspace when /Me answers %i",
      async (status) => {
        meStatus = status;
        const fetchMock = stubFetch(databricks);

        await expect(validate(withWorkspace())).rejects.toMatchObject({
          message: `Service principal ${APPLICATION_ID} can't call Databricks workspace ${WORKSPACE_ID} at ${WORKSPACE_URL}. Check the URL, and that the service principal is assigned to the workspace.`,
          data: { type: "insufficient_privileges" },
        });
        expect(databricksCalls(fetchMock).some((c) => isBinding(c.url))).toBe(
          false
        );
      }
    );

    it("refuses a URL that answers for another workspace", async () => {
      bindingWorkspaceId = "42";
      stubFetch(databricks);

      await expect(validate(withWorkspace())).rejects.toMatchObject({
        message: `Databricks workspace URL ${WORKSPACE_URL} belongs to workspace 42, not ${WORKSPACE_ID}. Check the URL saved for workspace ${WORKSPACE_ID} in P0.`,
        data: { type: "validation_error" },
      });
    });

    it("refuses a workspace without a metastore", async () => {
      stubFetch((url) =>
        isBinding(url)
          ? jsonResponse(
              { error_code: "METASTORE_DOES_NOT_EXIST", message: "none" },
              { status: 404 }
            )
          : databricks(url)
      );

      await expect(validate(withWorkspace())).rejects.toMatchObject({
        message: `Databricks workspace ${WORKSPACE_ID} has no Unity Catalog metastore. P0 needs one to confirm the workspace's URL. Assign the workspace a metastore, then try again.`,
        data: { type: "validation_error" },
      });
    });

    it("calls no account API without requireAccountAdmin", async () => {
      groups = [ADMINS];
      const fetchMock = stubFetch(databricks);

      await validate(withWorkspace({ requireWorkspaceAdmin: true }));

      expect(
        databricksCalls(fetchMock).filter((c) => c.url.startsWith(ACCOUNTS_URL))
      ).toEqual([]);
    });

    it("also checks account admin when both are required", async () => {
      groups = [ADMINS];
      stubFetch(databricks);

      await expect(
        validate(
          withWorkspace({
            requireAccountAdmin: true,
            requireWorkspaceAdmin: true,
          })
        )
      ).resolves.toMatchObject({
        servicePrincipal,
        workspace: { isAdmin: true },
      });
    });
  });

  describe("with requireWorkspaceAdmin", () => {
    it("refuses a principal whose /Me lacks the admins group", async () => {
      stubFetch(databricks);

      await expect(
        validate(withWorkspace({ requireWorkspaceAdmin: true }))
      ).rejects.toMatchObject({
        message: `Service principal ${APPLICATION_ID} is not an admin of Databricks workspace ${WORKSPACE_ID}`,
        data: { type: "insufficient_privileges" },
      });
    });

    it.each([
      ["no groups", undefined],
      ["a group named admins only by value", [{ value: "admins" }]],
    ])("refuses a /Me with %s", async (_, meGroups) => {
      groups = meGroups;
      stubFetch(databricks);

      await expect(
        validate(withWorkspace({ requireWorkspaceAdmin: true }))
      ).rejects.toMatchObject({ data: { type: "insufficient_privileges" } });
    });

    it("passes a principal in the admins group", async () => {
      groups = [USERS, ADMINS];
      stubFetch(databricks);

      await expect(
        validate(withWorkspace({ requireWorkspaceAdmin: true }))
      ).resolves.toMatchObject({ workspace: { isAdmin: true } });
    });
  });

  describe("input", () => {
    it.each<[string, InstallValidationInput]>([
      [
        "a workspace ID without its URL",
        { ...accountContext(), workspaceId: WORKSPACE_ID },
      ],
      [
        "a workspace URL without its ID",
        { ...accountContext(), workspaceUrl: WORKSPACE_URL },
      ],
      [
        "requireWorkspaceAdmin without a workspace",
        { ...accountContext(), requireWorkspaceAdmin: true },
      ],
      [
        "an account ID that isn't a GUID",
        accountContext({ accountId: "../x" }),
      ],
      [
        "a workspace ID that isn't digits",
        withWorkspace({ workspaceId: "../1" }),
      ],
      [
        "a workspace URL off the Databricks domains",
        withWorkspace({ workspaceUrl: "https://evil.example" }),
      ],
    ])("refuses %s before calling anything", async (_, input) => {
      const fetchMock = stubFetch(databricks);

      await expect(validate(input)).rejects.toThrow();
      expect(fetchMock).not.toHaveBeenCalled();
    });

    it("names the pair rule when one of the pair is missing", async () => {
      stubFetch(databricks);

      await expect(
        validate({ ...accountContext(), workspaceId: WORKSPACE_ID })
      ).rejects.toThrow(/workspaceId and workspaceUrl must be sent together/);
    });

    it("rejects a field it doesn't know instead of validating less", async () => {
      const fetchMock = stubFetch(databricks);

      await expect(
        validate({
          ...withWorkspace(),
          // @ts-expect-error a misspelled field, which the strict schema must refuse
          requireWorkspaceAdmn: true,
        })
      ).rejects.toThrow();
      expect(fetchMock).not.toHaveBeenCalled();
    });

    it.each([
      ["unset", undefined, /DOMAIN_PATTERN is not set/],
      ["empty", "  ", /DOMAIN_PATTERN is not set/],
      ["not a valid regex", "(example", /DOMAIN_PATTERN is not a valid regex/],
    ])(
      "fails before calling anything when DOMAIN_PATTERN is %s",
      async (_, pattern, message) => {
        vi.stubEnv(DOMAIN_PATTERN_ENV, pattern);
        const fetchMock = stubFetch(databricks);

        await expect(validate(withWorkspace())).rejects.toMatchObject({
          data: { type: "validation_error", message },
        });
        expect(fetchMock).not.toHaveBeenCalled();
      }
    );
  });
});
