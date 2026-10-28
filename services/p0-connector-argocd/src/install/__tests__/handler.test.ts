import { ConnectorError } from "@p0security/connector-core";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  ARGOCD_HOST,
  INSTANCE,
  NEVER_SHOWN,
  TOKEN,
  connectorError,
  logger,
  recordLogger,
} from "../../__tests__/fixtures.ts";
import {
  CAN_I,
  LIST_PROJECTS,
  PATCH_RBAC,
  READ_RBAC,
  USER_INFO,
  expectPhases,
  patches,
  postBodies,
} from "../../accesses/__tests__/helpers.ts";
import { ALLOWED_EMAIL_DOMAIN_PATTERN_ENV } from "../../allowlist.ts";
import {
  type FakeArgoCdState,
  installedState,
  newFakeArgoCd,
  rbacResource,
} from "../../argocd/__tests__/fake-argocd.ts";
import type { Instance } from "../../instance.ts";
import { connectorRouter } from "../../router.ts";
import { readApiToken } from "../../secrets.ts";

// The secret manager is `secrets.test.ts`'s business. Here the read answers
// with the token, or fails, as each test says.
vi.mock("../../secrets.ts");

const PATTERN = "example\\.com";

const VERSION = "GET /api/version";
const GET_APP = "GET /api/v1/applications/argocd";

/** The connector's own lines, which the install steps put in policy.csv. */
const CONNECTOR_LINES = [
  "p, role:p0-connector, applications, get, platform/argocd, allow",
  "p, role:p0-connector, applications, update//ConfigMap/argocd/argocd-rbac-cm, platform/argocd, allow",
  "p, role:p0-connector, projects, get, *, allow",
  "g, p0-connector, role:p0-connector",
  "",
].join("\n");

/** `argocd-rbac-cm` as the install steps leave it. */
const INSTALLED_DATA = {
  "policy.csv": `${CONNECTOR_LINES}p, role:dev, applications, get, */*, allow\n`,
  scopes: "[groups, email]",
};

/** An Argo CD every check passes on, unless overridden. */
const argoCdWith = (
  overrides: Partial<FakeArgoCdState> = {},
  data: Record<string, string> = INSTALLED_DATA
) =>
  newFakeArgoCd(
    installedState({
      rbac: { namespace: "argocd", data: { ...data } },
      ...overrides,
    })
  );

type ArgoCd = ReturnType<typeof argoCdWith>;

/**
 * Answers a call with `answer`'s response when it gives one, and as the fake
 * does otherwise.
 */
const intercept = (
  argocd: ArgoCd,
  answer: (method: string, path: string) => Response | undefined
) => {
  const fake = argocd.fetch.getMockImplementation();
  if (fake === undefined) throw new Error("the fake has no implementation");
  argocd.fetch.mockImplementation(
    async (url, init) =>
      answer(init?.method ?? "GET", new URL(url).pathname) ??
      (await fake(url, init))
  );
};

// Calling through the connector router also proves the `argocd` namespace is
// registered with its install router. The router's input type is what its
// parser returns, namespace and all; the tests also send what P0 might,
// which the parser fills in or refuses.
const validate = (input: object = INSTANCE) =>
  connectorRouter
    .createCaller({ logger })
    .argocd.install.validation.get(input as Instance);

/** The calls a validation that passes makes, phase by phase. */
const ALL_PHASES = [
  [VERSION],
  [USER_INFO],
  [GET_APP],
  [READ_RBAC],
  [LIST_PROJECTS],
  CAN_I,
  [PATCH_RBAC],
];

beforeEach(() => {
  vi.clearAllMocks();
  vi.stubEnv(ALLOWED_EMAIL_DOMAIN_PATTERN_ENV, PATTERN);
  vi.mocked(readApiToken).mockResolvedValue(TOKEN);
});

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  vi.unstubAllEnvs();
});

describe("install validation", () => {
  it("reports Argo CD's version and the connector's own pattern, after every check, in order", async () => {
    const argocd = argoCdWith();

    await expect(validate()).resolves.toStrictEqual({
      argoCdVersion: "v3.5.5+2f9b0d1",
      allowedEmailDomainPattern: PATTERN,
    });

    expect(readApiToken).toHaveBeenCalledWith(
      INSTANCE.secret,
      expect.anything()
    );
    expectPhases(argocd, ALL_PHASES);
  });

  // The patch proves the fine-grained update permission, which can-i can't
  // ask about. It changes nothing.
  it("sends an empty merge patch, and leaves argocd-rbac-cm as it was", async () => {
    const argocd = argoCdWith();

    await validate();

    expect(patches(argocd)).toEqual([{ data: {} }]);
    expect(postBodies(argocd)).toEqual([JSON.stringify('{"data":{}}')]);
    expect(argocd.state.rbac.data).toEqual(INSTALLED_DATA);
  });

  it("passes with P0's own lines in policy.p0.csv", async () => {
    argoCdWith(
      {},
      {
        ...INSTALLED_DATA,
        "policy.p0.csv":
          "g, alice@example.com, role:readonly\ng, bob@example.com, proj:payments:deployer\n",
      }
    );

    await expect(validate()).resolves.toMatchObject({
      argoCdVersion: "v3.5.5+2f9b0d1",
    });
  });

  // Argo CD skips a blank line, so one that is only space isn't foreign.
  it("passes with blank lines in policy.p0.csv", async () => {
    argoCdWith(
      {},
      {
        ...INSTALLED_DATA,
        "policy.p0.csv": "g, alice@example.com, role:readonly\n  \n\t\n",
      }
    );

    await expect(validate()).resolves.toMatchObject({
      argoCdVersion: "v3.5.5+2f9b0d1",
    });
  });

  // Argo CD trims a line, and so do a grant and a revoke looking for P0's.
  it("passes P0's lines with space around them, CRLF endings included", async () => {
    argoCdWith(
      {},
      {
        ...INSTALLED_DATA,
        "policy.p0.csv":
          "g, alice@example.com, role:readonly\r\n  g, bob@example.com, role:readonly \r\n",
      }
    );

    await expect(validate()).resolves.toMatchObject({
      argoCdVersion: "v3.5.5+2f9b0d1",
    });
  });

  it("logs what it validated", async () => {
    const log = recordLogger();
    argoCdWith();

    await validate();

    expect(log.lines()).toContainEqual([
      {
        url: INSTANCE.url,
        argoCdVersion: "v3.5.5+2f9b0d1",
        allowedEmailDomainPattern: PATTERN,
      },
      "validated the Argo CD instance",
    ]);
  });

  it("passes with an empty policy.p0.csv", async () => {
    argoCdWith({}, { ...INSTALLED_DATA, "policy.p0.csv": "" });

    await expect(validate()).resolves.toMatchObject({
      argoCdVersion: "v3.5.5+2f9b0d1",
    });
  });

  it("reads argocd-rbac-cm in the instance's namespace", async () => {
    const argocd = newFakeArgoCd(
      installedState({
        permissions: new Set([
          "applications/get/platform/argocd",
          "applications/update//ConfigMap/ops/argocd-rbac-cm/platform/argocd",
          "projects/get/*",
        ]),
        applications: [
          {
            name: "argocd",
            project: "platform",
            resources: [rbacResource("ops")],
          },
        ],
        rbac: { namespace: "ops", data: { ...INSTALLED_DATA } },
      })
    );

    await expect(
      validate({ ...INSTANCE, namespace: "ops" })
    ).resolves.toMatchObject({ allowedEmailDomainPattern: PATTERN });
    expect(patches(argocd)).toEqual([{ data: {} }]);
  });

  // What the allowlist will compile is the value less the whitespace around
  // it, so that is what is reported.
  it("reports the pattern trimmed, and otherwise as it is set", async () => {
    vi.stubEnv(ALLOWED_EMAIL_DOMAIN_PATTERN_ENV, " (.+\\.)?Example\\.com \n");
    argoCdWith();

    await expect(validate()).resolves.toMatchObject({
      allowedEmailDomainPattern: "(.+\\.)?Example\\.com",
    });
  });

  it("refuses an instance that isn't https before it reads the secret", async () => {
    const argocd = argoCdWith();

    await expect(
      validate({ ...INSTANCE, url: `http://${ARGOCD_HOST}` })
    ).rejects.toMatchObject({ code: "BAD_REQUEST" });

    expect(readApiToken).not.toHaveBeenCalled();
    expect(argocd.fetch).not.toHaveBeenCalled();
  });

  describe("the pattern step", () => {
    it.each<[what: string, pattern: string | undefined, problem: string]>([
      ["unset", undefined, "isn't set."],
      ["blank", "   ", "isn't set."],
      [
        "not a regex that compiles",
        "(example\\.com",
        "isn't a regular expression that compiles. The connector's log says why.",
      ],
    ])(
      "fails when the pattern is %s, before the secret is read or Argo CD is called",
      async (_case, pattern, problem) => {
        vi.stubEnv(ALLOWED_EMAIL_DOMAIN_PATTERN_ENV, pattern);
        const argocd = argoCdWith();

        const { data } = await connectorError(validate);

        expect(data).toEqual({
          type: "validation_error",
          message: `The connector's ALLOWED_EMAIL_DOMAIN_PATTERN ${problem} Set it to a regular expression for the email domains that may receive access.`,
          payload: { step: "pattern", host: ARGOCD_HOST },
        });
        expect(readApiToken).not.toHaveBeenCalled();
        expect(argocd.fetch).not.toHaveBeenCalled();
      }
    );

    // The regex engine's message quotes the pattern, so only the log has it.
    it("logs the regex engine's error, and keeps it out of the message", async () => {
      vi.stubEnv(ALLOWED_EMAIL_DOMAIN_PATTERN_ENV, "(example\\.com");
      const log = recordLogger();
      argoCdWith();

      const { data } = await connectorError(validate);

      expect(data.message).not.toContain("(example\\.com");
      expect(log.lines()).toContainEqual([
        {
          problem: {
            reason: "invalid_regex",
            detail:
              "Invalid regular expression: /(example\\.com/: Unterminated group",
          },
        },
        "the email domain allowlist is unusable; install validation fails",
      ]);
    });
  });

  describe("the secret step", () => {
    it("names the step and the instance when the read fails, and doesn't call Argo CD", async () => {
      vi.mocked(readApiToken).mockRejectedValue(
        new ConnectorError({
          type: "insufficient_privileges",
          message: "The connector isn't allowed to read the secret.",
          payload: { manager: "aws" },
        })
      );
      const argocd = argoCdWith();

      const { data } = await connectorError(validate);

      expect(data).toEqual({
        type: "insufficient_privileges",
        message: "The connector isn't allowed to read the secret.",
        payload: { step: "secret", host: ARGOCD_HOST, manager: "aws" },
      });
      expect(argocd.fetch).not.toHaveBeenCalled();
    });

    it("fails on a token that can't go in a header, without calling Argo CD", async () => {
      vi.mocked(readApiToken).mockResolvedValue("two words");
      const argocd = argoCdWith();

      const { data } = await connectorError(validate);

      expect(data.type).toBe("validation_error");
      expect(data.payload).toEqual({ step: "secret", host: ARGOCD_HOST });
      expect(data.message).toContain(
        "Store the p0-connector account's API token"
      );
      expect(argocd.fetch).not.toHaveBeenCalled();
    });

    it("passes on a bug, not dressed up as a step", async () => {
      vi.mocked(readApiToken).mockRejectedValue(new TypeError("a bug"));
      argoCdWith();

      await expect(validate()).rejects.toThrow("a bug");
    });
  });

  describe("the reachable step", () => {
    it("fails as unreachable when the connection is refused, and tries nothing else", async () => {
      const fetchMock = vi.fn(async () => {
        throw new TypeError("fetch failed", {
          cause: Object.assign(new Error("refused"), { code: "ECONNREFUSED" }),
        });
      });
      vi.stubGlobal("fetch", fetchMock);

      const { data } = await connectorError(validate);

      expect(data).toEqual({
        type: "upstream_unavailable",
        message: `The connector couldn't reach Argo CD at ${ARGOCD_HOST}: ECONNREFUSED. Check the instance's URL, and that the connector's network can reach it.`,
        payload: { step: "reachable", host: ARGOCD_HOST },
      });
      expect(fetchMock).toHaveBeenCalledTimes(1);
    });

    it("says the host doesn't resolve, as the customer's to fix", async () => {
      vi.stubGlobal(
        "fetch",
        vi.fn(async () => {
          throw new TypeError("fetch failed", {
            cause: Object.assign(new Error("lookup"), { code: "ENOTFOUND" }),
          });
        })
      );

      const { data } = await connectorError(validate);

      expect(data.type).toBe("validation_error");
      expect(data.payload).toEqual({
        step: "reachable",
        host: ARGOCD_HOST,
        code: "ENOTFOUND",
      });
    });

    it("fails when what answers isn't Argo CD", async () => {
      vi.stubGlobal(
        "fetch",
        vi.fn(async () => new Response("<html>hello</html>", { status: 200 }))
      );

      const { data } = await connectorError(validate);

      expect(data).toEqual({
        type: "validation_error",
        message: `${ARGOCD_HOST} didn't answer GET /api/version the way Argo CD does. Check that the instance's URL points at Argo CD.`,
        payload: { step: "reachable", host: ARGOCD_HOST },
      });
      expect(data.message).not.toContain("hello");
    });

    // Argo CD answers the version for anyone, so a refusal isn't Argo CD's.
    it.each([401, 403])(
      "blames what is in front of Argo CD when the version call is refused with %i",
      async (status) => {
        const argocd = argoCdWith();
        intercept(argocd, (_method, path) =>
          path === "/api/version"
            ? Response.json({ message: "go away" }, { status })
            : undefined
        );

        const { data } = await connectorError(validate);

        expect(data).toEqual({
          type: "insufficient_privileges",
          message: `Something in front of Argo CD at ${ARGOCD_HOST} refused the connector's call with ${status}: Argo CD itself answers GET /api/version for anyone. Let the connector through the proxy or gateway in front of the instance.`,
          payload: { step: "reachable", host: ARGOCD_HOST, status },
        });
        expect(argocd.calls()).toHaveLength(1);
      }
    );
  });

  describe("the version step", () => {
    it("fails on an Argo CD older than 3.0.0, naming the version it read", async () => {
      const argocd = argoCdWith({ version: "v2.14.11+8283115" });

      const { data } = await connectorError(validate);

      expect(data).toEqual({
        type: "validation_error",
        message: `Argo CD at ${ARGOCD_HOST} is version 2.14.11. The connector needs Argo CD 3.0.0 or later, the first whose policy can let an account patch argocd-rbac-cm alone. Upgrade Argo CD.`,
        payload: {
          step: "version",
          host: ARGOCD_HOST,
          argoCdVersion: "2.14.11",
        },
      });
      expectPhases(argocd, [[VERSION]]);
    });

    it("passes 3.0.0 itself", async () => {
      argoCdWith({ version: "v3.0.0+abcdef0" });

      await expect(validate()).resolves.toMatchObject({
        argoCdVersion: "v3.0.0+abcdef0",
      });
    });

    it("fails on a version it can't read, without quoting it", async () => {
      const argocd = argoCdWith({ version: "latest-and-greatest" });

      const { data } = await connectorError(validate);

      expect(data).toEqual({
        type: "validation_error",
        message: `Argo CD at ${ARGOCD_HOST} reports a version the connector can't read. It needs Argo CD 3.0.0 or later.`,
        payload: { step: "version", host: ARGOCD_HOST },
      });
      expectPhases(argocd, [[VERSION]]);
    });
  });

  describe("the account step", () => {
    // With anonymous access on, can-i and the project list would answer for
    // the anonymous user, and the self-check could pass falsely.
    it("fails on a token Argo CD answers as anonymous, before can-i or the project list", async () => {
      vi.mocked(readApiToken).mockResolvedValue("not-the-token");
      const argocd = argoCdWith({
        anonymousEnabled: true,
        anonymousPermissions: new Set(["projects/get/*"]),
      });

      const { data } = await connectorError(validate);

      expect(data).toEqual({
        type: "insufficient_privileges",
        message: `Argo CD at ${ARGOCD_HOST} didn't accept the connector's API token. Check that the secret holds a current API token of the p0-connector account, and that the account is enabled and has the apiKey capability.`,
        payload: { step: "account", host: ARGOCD_HOST },
      });
      expectPhases(argocd, [[VERSION], [USER_INFO]]);
    });

    it.each([
      [
        "another local account",
        { loggedIn: true, username: "admin", iss: "argocd" },
      ],
      [
        "an SSO user called p0-connector",
        {
          loggedIn: true,
          username: "p0-connector",
          iss: "https://sso.example.com",
        },
      ],
    ])(
      "fails on a token that is %s's, without quoting who",
      async (_case, userInfo) => {
        const argocd = argoCdWith();
        intercept(argocd, (_method, path) =>
          path === "/api/v1/session/userinfo"
            ? Response.json(userInfo)
            : undefined
        );

        const { data } = await connectorError(validate);

        expect(data).toEqual({
          type: "validation_error",
          message: `The API token in the secret for ${ARGOCD_HOST} isn't the p0-connector local account's. Generate one with "argocd account generate-token --account p0-connector" and store it in the secret.`,
          payload: { step: "account", host: ARGOCD_HOST },
        });
        expect(data.message).not.toContain("admin");
        expect(data.message).not.toContain("sso.example.com");
        expectPhases(argocd, [[VERSION], [USER_INFO]]);
      }
    );
  });

  describe("the managing_app step", () => {
    it("fails when the account can't read the managing Application, or it doesn't exist", async () => {
      const argocd = argoCdWith({ applications: [] });

      const { data } = await connectorError(validate);

      expect(data.type).toBe("insufficient_privileges");
      expect(data.payload).toEqual({
        step: "managing_app",
        host: ARGOCD_HOST,
        status: 403,
        permission: "applications, get",
      });
      expect(data.message).toContain("or that Application doesn't exist");
      expectPhases(argocd, [[VERSION], [USER_INFO], [GET_APP]]);
    });

    it("fails when the Application is in another project than the instance names, without quoting it", async () => {
      const argocd = argoCdWith({
        permissions: new Set([
          "applications/get/secret-project/argocd",
          "projects/get/*",
        ]),
        applications: [
          { name: "argocd", project: "secret-project", resources: [] },
        ],
      });

      const { data } = await connectorError(validate);

      expect(data).toEqual({
        type: "validation_error",
        message: `Application argocd on ${ARGOCD_HOST} isn't in project platform. Set the managing Application on the Argo CD instance in P0 to <project>/argocd, with the project the Application is in.`,
        payload: { step: "managing_app", host: ARGOCD_HOST },
      });
      expect(data.message).not.toContain("secret-project");
      expectPhases(argocd, [[VERSION], [USER_INFO], [GET_APP]]);
    });
  });

  describe("the rbac_config_map step", () => {
    it("fails as unsupported when the Application doesn't manage argocd-rbac-cm", async () => {
      const argocd = argoCdWith({
        applications: [{ name: "argocd", project: "platform", resources: [] }],
      });

      const { data } = await connectorError(validate);

      expect(data).toEqual({
        type: "validation_error",
        message: `Application argocd on ${ARGOCD_HOST} doesn't manage ConfigMap argocd/argocd-rbac-cm. The connector supports only an Argo CD whose argocd-rbac-cm an Application deploys: set the managing Application and the namespace on the Argo CD instance in P0 to that Application and argocd-rbac-cm's namespace.`,
        payload: {
          step: "rbac_config_map",
          host: ARGOCD_HOST,
          app: "argocd",
          namespace: "argocd",
        },
      });
      expectPhases(argocd, [[VERSION], [USER_INFO], [GET_APP], [READ_RBAC]]);
    });

    it("fails when what comes back isn't argocd-rbac-cm", async () => {
      const argocd = argoCdWith();
      intercept(argocd, (method, path) =>
        method === "GET" && path.endsWith("/resource")
          ? Response.json({ manifest: JSON.stringify({ kind: "Secret" }) })
          : undefined
      );

      const { data } = await connectorError(validate);

      expect(data.type).toBe("validation_error");
      expect(data.payload).toEqual({
        step: "rbac_config_map",
        host: ARGOCD_HOST,
      });
    });
  });

  describe("the scopes step", () => {
    it("fails when scopes doesn't include email, as when it is left out", async () => {
      const argocd = argoCdWith({}, { "policy.csv": CONNECTOR_LINES });

      const { data } = await connectorError(validate);

      expect(data).toEqual({
        type: "validation_error",
        message: `argocd-rbac-cm on Argo CD at ${ARGOCD_HOST} doesn't have email in scopes, so Argo CD won't match the lines P0 writes, which name users by email. Add email to scopes, such as "[groups, email]".`,
        payload: { step: "scopes", host: ARGOCD_HOST },
      });
      expectPhases(argocd, [[VERSION], [USER_INFO], [GET_APP], [READ_RBAC]]);
    });

    it("fails when scopes isn't a list the connector can read, without quoting it", async () => {
      argoCdWith({}, { ...INSTALLED_DATA, scopes: "- groups\n- email" });

      const { data } = await connectorError(validate);

      expect(data).toEqual({
        type: "validation_error",
        message: `The connector can't read scopes in argocd-rbac-cm on Argo CD at ${ARGOCD_HOST}. Write it as a flow list on one line, such as "[groups, email]".`,
        payload: { step: "scopes", host: ARGOCD_HOST },
      });
    });
  });

  describe("the p0_policy step", () => {
    it("fails when policy.p0.csv has a line P0 doesn't write, naming its number and never its content", async () => {
      const argocd = argoCdWith(
        {},
        {
          ...INSTALLED_DATA,
          "policy.p0.csv":
            "g, alice@example.com, role:readonly\n\ng, mallory@example.com, role:admin # hand-made\n",
        }
      );

      const { data } = await connectorError(validate);

      expect(data).toEqual({
        type: "validation_error",
        message: `policy.p0.csv in argocd-rbac-cm on Argo CD at ${ARGOCD_HOST} has a line P0 didn't write (line 3). The connector owns that key: move the line to another policy key, or remove it.`,
        payload: { step: "p0_policy", host: ARGOCD_HOST, lines: "3" },
      });
      expect(data.message).not.toContain("mallory");
      expectPhases(argocd, [[VERSION], [USER_INFO], [GET_APP], [READ_RBAC]]);
    });

    it("names every such line", async () => {
      argoCdWith(
        {},
        {
          ...INSTALLED_DATA,
          "policy.p0.csv":
            "p, role:x, applications, get, */*, allow\ng, alice@example.com, role:readonly\n# g, bob@example.com, role:readonly",
        }
      );

      const { data } = await connectorError(validate);

      expect(data.message).toContain("(lines 1, 3)");
      expect(data.payload).toMatchObject({ lines: "1; 3" });
    });
  });

  describe("the policy_loaded step", () => {
    it("fails when Argo CD refuses a line of the policy, naming the key and line, never the content", async () => {
      const argocd = argoCdWith(
        {},
        {
          ...INSTALLED_DATA,
          "policy.team.csv":
            "g, alice@example.com, role:dev\ng, broken-secret-line\n",
        }
      );

      const { data } = await connectorError(validate);

      expect(data.type).toBe("validation_error");
      expect(data.payload).toEqual({
        step: "policy_loaded",
        host: ARGOCD_HOST,
        reason: "policy_not_loaded",
        lines: "policy.team.csv line 2",
      });
      expect(data.message).toContain("(policy.team.csv line 2)");
      expect(data.message).not.toContain("broken-secret-line");
      expectPhases(argocd, [[VERSION], [USER_INFO], [GET_APP], [READ_RBAC]]);
    });
  });

  describe("the projects step", () => {
    it("fails when the project list is refused", async () => {
      const argocd = argoCdWith();
      intercept(argocd, (_method, path) =>
        path === "/api/v1/projects"
          ? Response.json({}, { status: 403 })
          : undefined
      );

      const { data } = await connectorError(validate);

      expect(data.type).toBe("insufficient_privileges");
      expect(data.payload).toEqual({
        step: "projects",
        host: ARGOCD_HOST,
        status: 403,
        permission: "projects, get",
      });
      expectPhases(argocd, [
        [VERSION],
        [USER_INFO],
        [GET_APP],
        [READ_RBAC],
        [LIST_PROJECTS],
      ]);
    });
  });

  describe("the patch step", () => {
    it("fails when the account may not patch argocd-rbac-cm, naming the permission", async () => {
      const argocd = argoCdWith({
        permissions: new Set([
          "applications/get/platform/argocd",
          "projects/get/*",
        ]),
      });

      const { data } = await connectorError(validate);

      expect(data.type).toBe("insufficient_privileges");
      expect(data.payload).toEqual({
        step: "patch",
        host: ARGOCD_HOST,
        status: 403,
        permission: "applications, update//ConfigMap/argocd/argocd-rbac-cm",
      });
      expectPhases(argocd, ALL_PHASES);
      expect(argocd.state.rbac.data).toEqual(INSTALLED_DATA);
    });
  });

  describe("the self_check step", () => {
    it("fails when the account may do more than it needs, naming what", async () => {
      const argocd = argoCdWith({
        permissions: new Set([
          ...installedState().permissions,
          "applications/sync/*/*",
          "clusters/update/*",
        ]),
      });

      const { data } = await connectorError(validate);

      expect(data.type).toBe("validation_error");
      expect(data.payload).toEqual({
        step: "self_check",
        host: ARGOCD_HOST,
        reason: "self_check_failed",
        held: "applications, sync, */*; clusters, update, *",
      });
      // An account that may do too much never makes the empty write.
      expectPhases(argocd, ALL_PHASES.slice(0, -1));
      expect(patches(argocd)).toEqual([]);
    });

    it("fails when can-i fails", async () => {
      const argocd = argoCdWith();
      intercept(argocd, (_method, path) =>
        path.startsWith("/api/v1/account/can-i/")
          ? Response.json({}, { status: 503 })
          : undefined
      );

      const { data } = await connectorError(validate);

      expect(data.type).toBe("upstream_unavailable");
      expect(data.payload).toMatchObject({ step: "self_check", status: 503 });
      expect(patches(argocd)).toEqual([]);
    });
  });

  describe("the token and the secret's pointer", () => {
    it.each<[string, Partial<FakeArgoCdState>]>([
      ["validation passes", {}],
      ["validation fails", { applications: [] }],
    ])(
      "reach no log line, no logger's bindings and no error when %s",
      async (_case, state) => {
        const log = recordLogger();
        argoCdWith(state);

        const outcome = await validate().catch((error: unknown) => error);

        expect(log.lines()).not.toHaveLength(0);
        const seen = log.seen(outcome);
        for (const marker of NEVER_SHOWN) expect(seen).not.toContain(marker);
      }
    );
  });
});
