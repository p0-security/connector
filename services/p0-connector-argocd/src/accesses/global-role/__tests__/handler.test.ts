import type { Logger } from "@p0security/connector";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  ARGOCD_HOST,
  NEVER_SHOWN,
  connectorError,
  logger,
  recordLogger,
} from "../../../__tests__/fixtures.ts";
import { ALLOWED_EMAIL_DOMAIN_PATTERN_ENV } from "../../../allowlist.ts";
import {
  type FakeArgoCdState,
  installedState,
  newFakeArgoCd,
} from "../../../argocd/__tests__/fake-argocd.ts";
import type { ConnectArgoCd } from "../../../argocd/client.ts";
import { argoCdRefusalReason } from "../../../refusals.ts";
import {
  CAN_I,
  LIST_PROJECTS,
  PARSED_INSTANCE,
  PATCH_RBAC,
  PATTERN,
  READ_RBAC,
  USER_INFO,
  connectWith,
  dropPatches,
  expectPhases,
  patches,
  postBodies,
  userBodyOf,
} from "../../__tests__/helpers.ts";
import { newGlobalRolePrimitives } from "../handler.ts";

const ALICE = "alice@example.com";

const CUSTOMER_POLICY = [
  "p, role:dev, applications, get, */*, allow",
  "p, role:ops, applications, sync, */*, allow",
  "g, role:lead, role:dev",
  "",
].join("\n");

/** The installed state, with `data` as `argocd-rbac-cm`'s keys. */
const withData = (data: Record<string, string>): FakeArgoCdState =>
  installedState({ rbac: { namespace: "argocd", data } });

const contextFor = (role: string) => ({
  ...PARSED_INSTANCE,
  requestId: "req-1",
  role,
});

const primitives = (
  connect: ConnectArgoCd = connectWith(),
  log: Logger = logger
) => newGlobalRolePrimitives(log, connect);

const grant = (
  role: string,
  email = ALICE,
  connect: ConnectArgoCd = connectWith()
) =>
  primitives(connect).setPoliciesForUser(
    contextFor(role),
    email,
    userBodyOf(email),
    [{ role }]
  );

const revoke = (
  role: string,
  email = ALICE,
  connect: ConnectArgoCd = connectWith()
) =>
  primitives(connect).setPoliciesForUser(
    contextFor(role),
    email,
    userBodyOf(email),
    [{ role: null }]
  );

/** The refusal's reason, checked to be one of the closed set. */
const reasonOf = async (run: () => Promise<unknown>) => {
  const { data } = await connectorError(run);
  expect(data.type).toBe("validation_error");
  return argoCdRefusalReason.parse(data.payload.reason);
};

beforeEach(() => {
  vi.clearAllMocks();
  vi.stubEnv(ALLOWED_EMAIL_DOMAIN_PATTERN_ENV, PATTERN);
});

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  vi.unstubAllEnvs();
});

describe("a global role grant", () => {
  it("adds P0's line to policy.p0.csv, after the self-check, and reads it back", async () => {
    const argocd = newFakeArgoCd(withData({ "policy.csv": CUSTOMER_POLICY }));

    await grant("role:dev");

    expect(argocd.state.rbac.data).toEqual({
      "policy.csv": CUSTOMER_POLICY,
      "policy.p0.csv": "g, alice@example.com, role:dev\n",
    });
    expectPhases(argocd, [
      [USER_INFO],
      CAN_I,
      [READ_RBAC, LIST_PROJECTS],
      [PATCH_RBAC],
      [READ_RBAC],
    ]);
  });

  // The connector never changes its own privileges: the patch body is the
  // one key, and nothing it writes names the connector's account or role.
  it("sends a patch that carries policy.p0.csv and nothing else", async () => {
    const argocd = newFakeArgoCd(
      withData({
        "policy.csv": CUSTOMER_POLICY,
        "policy.p0.csv": "g, bob@example.com, role:ops\n",
      })
    );

    await grant("role:dev");

    expect(patches(argocd)).toEqual([
      {
        data: {
          "policy.p0.csv":
            "g, bob@example.com, role:ops\ng, alice@example.com, role:dev\n",
        },
      },
    ]);
    const [body = ""] = postBodies(argocd);
    expect(JSON.parse(JSON.parse(body) as string)).toStrictEqual({
      data: {
        "policy.p0.csv":
          "g, bob@example.com, role:ops\ng, alice@example.com, role:dev\n",
      },
    });
    expect(body).not.toContain("p0-connector");
  });

  it("writes the email in lower case", async () => {
    const argocd = newFakeArgoCd(withData({ "policy.csv": CUSTOMER_POLICY }));

    await grant("role:dev", "Alice@Example.COM");

    expect(argocd.state.rbac.data?.["policy.p0.csv"]).toBe(
      "g, alice@example.com, role:dev\n"
    );
  });

  // A grant retried after its write landed: P0's own line isn't overlap.
  it("succeeds without a write when P0's line is there already", async () => {
    const data = {
      "policy.csv": CUSTOMER_POLICY,
      "policy.p0.csv": "  g, alice@example.com, role:dev \n",
    };
    const argocd = newFakeArgoCd(withData({ ...data }));

    await grant("role:dev");

    expect(argocd.state.rbac.data).toEqual(data);
    expectPhases(argocd, [[USER_INFO], CAN_I, [READ_RBAC, LIST_PROJECTS]]);
  });

  it("grants a built-in role no line names", async () => {
    const argocd = newFakeArgoCd(withData({}));

    await grant("role:readonly");

    expect(argocd.state.rbac.data).toEqual({
      "policy.p0.csv": "g, alice@example.com, role:readonly\n",
    });
  });

  it("grants a role only a g line names", async () => {
    const argocd = newFakeArgoCd(withData({ "policy.csv": CUSTOMER_POLICY }));

    await grant("role:lead");

    expect(argocd.state.rbac.data?.["policy.p0.csv"]).toBe(
      "g, alice@example.com, role:lead\n"
    );
  });

  it("reads argocd-rbac-cm in the instance's namespace", async () => {
    const state = installedState({
      rbac: { namespace: "ops", data: { "policy.csv": CUSTOMER_POLICY } },
    });
    state.permissions.add(
      "applications/update//ConfigMap/ops/argocd-rbac-cm/platform/argocd"
    );
    state.applications = [
      {
        name: "argocd",
        project: "platform",
        resources: [
          {
            version: "v1",
            kind: "ConfigMap",
            namespace: "ops",
            name: "argocd-rbac-cm",
          },
        ],
      },
    ];
    const argocd = newFakeArgoCd(state);

    await primitives().setPoliciesForUser(
      { ...contextFor("role:dev"), namespace: "ops" },
      ALICE,
      userBodyOf(ALICE),
      [{ role: "role:dev" }]
    );

    expect(argocd.state.rbac.data?.["policy.p0.csv"]).toBe(
      "g, alice@example.com, role:dev\n"
    );
  });

  describe("refuses, before the secret is read or Argo CD is called,", () => {
    it.each([
      [
        "an email in a domain the allowlist doesn't allow",
        "role:dev",
        "mallory@evil.io",
        "domain_not_allowed",
      ],
      [
        "the connector's own role",
        "role:p0-connector",
        ALICE,
        "connector_role",
      ],
      [
        "a user that isn't an email P0 writes",
        "role:dev",
        "alice smith@example.com",
        "not_an_email",
      ],
    ])("%s", async (_case, role, email, reason) => {
      const argocd = newFakeArgoCd(installedState());
      const connect = connectWith();

      await expect(reasonOf(() => grant(role, email, connect))).resolves.toBe(
        reason
      );
      expect(connect).not.toHaveBeenCalled();
      expect(argocd.fetch).not.toHaveBeenCalled();
    });

    it("every email when the allowlist is unset", async () => {
      vi.stubEnv(ALLOWED_EMAIL_DOMAIN_PATTERN_ENV, "");
      const argocd = newFakeArgoCd(installedState());

      await expect(reasonOf(() => grant("role:dev"))).resolves.toBe(
        "domain_pattern_unusable"
      );
      expect(argocd.fetch).not.toHaveBeenCalled();
    });
  });

  it("names the role in a connector_role refusal", async () => {
    newFakeArgoCd(installedState());

    const { data } = await connectorError(() => grant("role:p0-connector"));

    expect(data).toEqual({
      type: "validation_error",
      message: "P0 never grants role:p0-connector, the connector's own role.",
      payload: {
        host: ARGOCD_HOST,
        role: "role:p0-connector",
        reason: "connector_role",
      },
    });
  });

  it("names the email in a not_an_email refusal", async () => {
    newFakeArgoCd(installedState());

    const { data } = await connectorError(() =>
      grant("role:dev", "alice smith@example.com")
    );

    expect(data).toEqual({
      type: "validation_error",
      message:
        "alice smith@example.com isn't an email the Argo CD connector can grant a role to.",
      payload: { host: ARGOCD_HOST, reason: "not_an_email" },
    });
  });

  // With anonymous access on, can-i would answer for the anonymous user.
  it("fails on a token Argo CD answers as anonymous, before the self-check", async () => {
    const argocd = newFakeArgoCd(installedState({ anonymousEnabled: true }));

    const { data } = await connectorError(() =>
      grant("role:dev", ALICE, connectWith("not-the-token"))
    );

    expect(data.type).toBe("insufficient_privileges");
    expect(data.message).toContain("didn't accept the connector's API token");
    expectPhases(argocd, [[USER_INFO]]);
  });

  it("refuses with self_check_failed when the account may sync any application, and reads nothing", async () => {
    const state = withData({ "policy.csv": CUSTOMER_POLICY });
    state.permissions.add("applications/sync/*/*");
    const argocd = newFakeArgoCd(state);

    await expect(reasonOf(() => grant("role:dev"))).resolves.toBe(
      "self_check_failed"
    );
    expectPhases(argocd, [[USER_INFO], CAN_I]);
    expect(argocd.state.rbac.data?.["policy.p0.csv"]).toBeUndefined();
  });

  it("refuses the default role", async () => {
    const argocd = newFakeArgoCd(
      withData({ "policy.csv": CUSTOMER_POLICY, "policy.default": "role:dev" })
    );

    const { data } = await connectorError(() => grant("role:dev"));

    expect(data).toEqual({
      type: "validation_error",
      message: `role:dev is the default role on Argo CD at ${ARGOCD_HOST}: every user holds it already.`,
      payload: { host: ARGOCD_HOST, role: "role:dev", reason: "default_role" },
    });
    expect(patches(argocd)).toEqual([]);
  });

  it("refuses a role no line names", async () => {
    const argocd = newFakeArgoCd(withData({ "policy.csv": CUSTOMER_POLICY }));

    const { data } = await connectorError(() => grant("role:nobody"));

    expect(data).toEqual({
      type: "validation_error",
      message: `Argo CD at ${ARGOCD_HOST} has no role role:nobody.`,
      payload: {
        host: ARGOCD_HOST,
        role: "role:nobody",
        reason: "role_not_found",
      },
    });
    expect(patches(argocd)).toEqual([]);
  });

  // A role that was removed from the customer's policy doesn't live on in
  // the lines P0 wrote for it.
  it("refuses a role only a line of P0's names", async () => {
    newFakeArgoCd(
      withData({
        "policy.csv": CUSTOMER_POLICY,
        "policy.p0.csv": "g, bob@example.com, role:gone\n",
      })
    );

    await expect(reasonOf(() => grant("role:gone"))).resolves.toBe(
      "role_not_found"
    );
  });

  it("refuses with policy_not_loaded when a line Argo CD refuses is anywhere, naming where but not what", async () => {
    const argocd = newFakeArgoCd(
      withData({
        "policy.csv": `${CUSTOMER_POLICY}g, secret-looking, line, extra\n`,
        "policy.p0.csv": "g, bob@example.com, role:ops\nnonsense\n",
      })
    );

    const { data } = await connectorError(() => grant("role:dev"));

    expect(data).toEqual({
      type: "validation_error",
      message: `argocd-rbac-cm on Argo CD at ${ARGOCD_HOST} has a line Argo CD refuses (policy.csv line 4, policy.p0.csv line 2), so Argo CD keeps enforcing the policy it had before it, and a new line wouldn't take effect. Fix or remove that line.`,
      payload: {
        host: ARGOCD_HOST,
        lines: "policy.csv line 4; policy.p0.csv line 2",
        reason: "policy_not_loaded",
      },
    });
    expect(JSON.stringify(data)).not.toContain("secret-looking");
    expect(patches(argocd)).toEqual([]);
  });

  it("succeeds on P0's own line even when a line Argo CD refuses is there", async () => {
    const argocd = newFakeArgoCd(
      withData({
        "policy.csv": `${CUSTOMER_POLICY}nonsense\n`,
        "policy.p0.csv": "g, alice@example.com, role:dev\n",
      })
    );

    await grant("role:dev");

    expect(patches(argocd)).toEqual([]);
  });

  describe("refuses with already_held a role the user holds", () => {
    it.each([
      [
        "through a customer's g line",
        { "policy.csv": `${CUSTOMER_POLICY}g, alice@example.com, role:dev\n` },
      ],
      [
        "through another policy key",
        {
          "policy.csv": CUSTOMER_POLICY,
          "policy.team.csv": "g, alice@example.com, role:dev\n",
        },
      ],
      [
        "through a role that inherits it",
        { "policy.csv": `${CUSTOMER_POLICY}g, alice@example.com, role:lead\n` },
      ],
      [
        "through policy.default",
        { "policy.csv": CUSTOMER_POLICY, "policy.default": "role:lead" },
      ],
      [
        "through a line in policy.p0.csv that isn't P0's spelling",
        {
          "policy.csv": CUSTOMER_POLICY,
          "policy.p0.csv": "g,alice@example.com,role:dev\n",
        },
      ],
    ])("%s", async (_case, data) => {
      const argocd = newFakeArgoCd(withData(data));

      await expect(reasonOf(() => grant("role:dev"))).resolves.toBe(
        "already_held"
      );
      expect(patches(argocd)).toEqual([]);
    });

    it("through a project role's group that is their email", async () => {
      const state = withData({
        "policy.csv": `${CUSTOMER_POLICY}g, proj:payments:deployer, role:dev\n`,
      });
      state.projects = [
        { name: "payments", roles: [{ name: "deployer", groups: [ALICE] }] },
      ];
      newFakeArgoCd(state);

      await expect(reasonOf(() => grant("role:dev"))).resolves.toBe(
        "already_held"
      );
    });

    it("and says so", async () => {
      newFakeArgoCd(
        withData({
          "policy.csv": `${CUSTOMER_POLICY}g, alice@example.com, role:dev\n`,
        })
      );

      const { data } = await connectorError(() => grant("role:dev"));

      expect(data).toEqual({
        type: "validation_error",
        message: `alice@example.com already holds role:dev on Argo CD at ${ARGOCD_HOST}.`,
        payload: {
          host: ARGOCD_HOST,
          kind: "global",
          role: "role:dev",
          reason: "already_held",
        },
      });
    });
  });

  // A broader role isn't the same role.
  it("grants a role the user holds a broader one than", async () => {
    const argocd = newFakeArgoCd(
      withData({
        "policy.csv": `${CUSTOMER_POLICY}g, alice@example.com, role:admin\n`,
      })
    );

    await grant("role:dev");

    expect(argocd.state.rbac.data?.["policy.p0.csv"]).toBe(
      "g, alice@example.com, role:dev\n"
    );
  });

  it("fails with dependency_violation when the read after the patch doesn't show the line", async () => {
    const argocd = newFakeArgoCd(withData({ "policy.csv": CUSTOMER_POLICY }));
    dropPatches(argocd);

    const { data } = await connectorError(() => grant("role:dev"));

    expect(data).toEqual({
      type: "dependency_violation",
      message: `Argo CD at ${ARGOCD_HOST} accepted the change to policy.p0.csv in argocd-rbac-cm, but reading it back, policy.p0.csv doesn't have the line. Check argocd-rbac-cm, then retry the grant.`,
      payload: { host: ARGOCD_HOST },
    });
  });

  it("fails as Argo CD's error says when the managing app doesn't manage argocd-rbac-cm", async () => {
    const state = withData({});
    state.applications = [
      { name: "argocd", project: "platform", resources: [] },
    ];
    newFakeArgoCd(state);

    const { data } = await connectorError(() => grant("role:dev"));

    expect(data.type).toBe("validation_error");
    expect(data.payload).toEqual({
      host: ARGOCD_HOST,
      app: "argocd",
      namespace: "argocd",
    });
  });

  it("fails with insufficient_privileges when the account may not patch", async () => {
    const state = withData({ "policy.csv": CUSTOMER_POLICY });
    state.permissions.delete(
      "applications/update//ConfigMap/argocd/argocd-rbac-cm/platform/argocd"
    );
    newFakeArgoCd(state);

    const { data } = await connectorError(() => grant("role:dev"));

    expect(data.type).toBe("insufficient_privileges");
    expect(data.payload).toMatchObject({ status: 403 });
  });

  it("logs neither the email nor the token", async () => {
    const log = recordLogger();
    newFakeArgoCd(withData({ "policy.csv": CUSTOMER_POLICY }));

    await primitives(connectWith(), logger).setPoliciesForUser(
      contextFor("role:dev"),
      ALICE,
      userBodyOf(ALICE),
      [{ role: "role:dev" }]
    );

    const seen = log.seen();
    expect(seen).not.toContain("alice");
    for (const secret of NEVER_SHOWN) expect(seen).not.toContain(secret);
  });
});

describe("a global role revoke", () => {
  it("removes P0's line and leaves every other line, a customer's for the same grant included", async () => {
    const argocd = newFakeArgoCd(
      withData({
        "policy.csv": `${CUSTOMER_POLICY}g, alice@example.com, role:dev\n`,
        "policy.p0.csv":
          "g, bob@example.com, role:dev\ng, alice@example.com, role:dev\ng, alice@example.com, role:ops\n",
      })
    );

    await revoke("role:dev");

    expect(argocd.state.rbac.data).toEqual({
      "policy.csv": `${CUSTOMER_POLICY}g, alice@example.com, role:dev\n`,
      "policy.p0.csv":
        "g, bob@example.com, role:dev\ng, alice@example.com, role:ops\n",
    });
    expectPhases(argocd, [[USER_INFO], [READ_RBAC], [PATCH_RBAC], [READ_RBAC]]);
  });

  it("sends a patch that carries policy.p0.csv and nothing else", async () => {
    const argocd = newFakeArgoCd(
      withData({ "policy.p0.csv": "g, alice@example.com, role:dev\n" })
    );

    await revoke("role:dev");

    expect(patches(argocd)).toStrictEqual([{ data: { "policy.p0.csv": "" } }]);
    expect(postBodies(argocd).join("")).not.toContain("p0-connector");
  });

  it("matches the email in any case", async () => {
    const argocd = newFakeArgoCd(
      withData({ "policy.p0.csv": "g, alice@example.com, role:dev\n" })
    );

    await revoke("role:dev", "ALICE@example.com");

    expect(argocd.state.rbac.data?.["policy.p0.csv"]).toBe("");
  });

  it.each([
    [
      "policy.p0.csv doesn't have the line",
      { "policy.p0.csv": "g, bob@example.com, role:dev\n" },
    ],
    ["there is no policy.p0.csv", { "policy.csv": CUSTOMER_POLICY }],
    ["argocd-rbac-cm has no keys", {}],
  ])("succeeds without a write when %s", async (_case, data) => {
    const argocd = newFakeArgoCd(withData({ ...data }));

    await revoke("role:dev");

    expect(argocd.state.rbac.data).toEqual(data);
    expectPhases(argocd, [[USER_INFO], [READ_RBAC]]);
  });

  // Taking access away depends on neither.
  it("checks neither the allowlist nor the account's privileges", async () => {
    vi.stubEnv(ALLOWED_EMAIL_DOMAIN_PATTERN_ENV, "");
    const state = withData({
      "policy.p0.csv": "g, mallory@evil.io, role:dev\n",
    });
    state.permissions.add("applications/sync/*/*");
    const argocd = newFakeArgoCd(state);

    await revoke("role:dev", "mallory@evil.io");

    expect(argocd.state.rbac.data?.["policy.p0.csv"]).toBe("");
    expect(argocd.calls().some((call) => call.includes("can-i"))).toBe(false);
  });

  it("removes the line when a line Argo CD refuses is there", async () => {
    const argocd = newFakeArgoCd(
      withData({
        "policy.csv": "nonsense\n",
        "policy.p0.csv": "g, alice@example.com, role:dev\n",
      })
    );

    await revoke("role:dev");

    expect(argocd.state.rbac.data?.["policy.p0.csv"]).toBe("");
  });

  it.each([
    ["the connector's own role", "role:p0-connector", ALICE],
    ["an email P0 doesn't write", "role:dev", "alice smith@example.com"],
  ])(
    "succeeds without calling Argo CD for %s, which P0 never wrote a line for",
    async (_case, role, email) => {
      const argocd = newFakeArgoCd(installedState());
      const connect = connectWith();

      await revoke(role, email, connect);

      expect(connect).not.toHaveBeenCalled();
      expect(argocd.fetch).not.toHaveBeenCalled();
    }
  );

  it("fails on a token Argo CD answers as anonymous", async () => {
    const argocd = newFakeArgoCd(installedState({ anonymousEnabled: true }));

    const { data } = await connectorError(() =>
      revoke("role:dev", ALICE, connectWith("not-the-token"))
    );

    expect(data.type).toBe("insufficient_privileges");
    expectPhases(argocd, [[USER_INFO]]);
  });

  it("fails with dependency_violation when the read after the patch still shows the line", async () => {
    const argocd = newFakeArgoCd(
      withData({ "policy.p0.csv": "g, alice@example.com, role:dev\n" })
    );
    dropPatches(argocd);

    const { data } = await connectorError(() => revoke("role:dev"));

    expect(data).toEqual({
      type: "dependency_violation",
      message: `Argo CD at ${ARGOCD_HOST} accepted the change to policy.p0.csv in argocd-rbac-cm, but reading it back, policy.p0.csv still has the line. Check argocd-rbac-cm, then retry the revoke.`,
      payload: { host: ARGOCD_HOST },
    });
  });
});

describe("setPoliciesForUser", () => {
  it.each([
    ["no policy", []],
    ["two policies", [{ role: "role:dev" }, { role: null }]],
  ])("refuses %s as P0's bug", async (_case, policies) => {
    const argocd = newFakeArgoCd(installedState());

    const { data } = await connectorError(() =>
      primitives().setPoliciesForUser(
        contextFor("role:dev"),
        ALICE,
        userBodyOf(ALICE),
        policies
      )
    );

    expect(data).toEqual({
      type: "unknown",
      message: `Expected exactly 1 policy for an Argo CD global role, got ${policies.length}`,
      payload: { requestId: "req-1", nPolicies: policies.length },
    });
    expect(argocd.fetch).not.toHaveBeenCalled();
  });

  // The router's schema refuses such a role; the primitives hold to the
  // line's own rules too.
  it("refuses a role P0 couldn't write as one the instance hasn't", async () => {
    const argocd = newFakeArgoCd(installedState());
    const connect = connectWith();

    const { data } = await connectorError(() =>
      grant("role:bad name", ALICE, connect)
    );

    expect(data).toEqual({
      type: "validation_error",
      message: `Argo CD at ${ARGOCD_HOST} has no role P0 can grant by that name.`,
      payload: { host: ARGOCD_HOST, reason: "role_not_found" },
    });
    expect(connect).not.toHaveBeenCalled();
    expect(argocd.fetch).not.toHaveBeenCalled();
  });

  it("refuses a grant of a role other than the request's as P0's bug", async () => {
    const argocd = newFakeArgoCd(installedState());

    const { data } = await connectorError(() =>
      primitives().setPoliciesForUser(
        contextFor("role:dev"),
        ALICE,
        userBodyOf(ALICE),
        [{ role: "role:admin" }]
      )
    );

    expect(data).toEqual({
      type: "unknown",
      message:
        "P0 asked the Argo CD connector to grant a role other than the request's.",
      payload: { requestId: "req-1" },
    });
    expect(argocd.fetch).not.toHaveBeenCalled();
  });
});

describe("the user primitives", () => {
  it("refuse to create a user, as P0's bug", async () => {
    const { data } = await connectorError(() =>
      primitives().createUser(contextFor("role:dev"), {
        instanceId: "p0-argocd",
        email: ALICE,
      })
    );

    expect(data).toEqual({
      type: "unknown",
      message:
        "P0 asked the Argo CD connector to create an Argo CD user, which it never does.",
      payload: { requestId: "req-1" },
    });
  });
});

describe("the role lister", () => {
  it("lists the built-ins and every role the customer's keys name, less the connector's and the default", async () => {
    const argocd = newFakeArgoCd(
      withData({
        "policy.csv": `p, role:p0-connector, projects, get, *, allow\ng, p0-connector, role:p0-connector\n${CUSTOMER_POLICY}`,
        "policy.default": "role:readonly",
        "policy.p0.csv": "g, bob@example.com, role:gone\n",
      })
    );

    await expect(
      primitives().list({ type: "role", context: PARSED_INSTANCE })
    ).resolves.toEqual(
      ["role:admin", "role:dev", "role:lead", "role:ops"].map((role) => ({
        key: role,
        value: role,
      }))
    );
    // No projects: a global role is never an AppProject's.
    expectPhases(argocd, [[USER_INFO], [READ_RBAC]]);
  });

  it.each([
    [
      "a role the instance has",
      "role:ops",
      [{ key: "role:ops", value: "role:ops" }],
    ],
    ["a role it doesn't", "role:nobody", []],
  ])("answers for %s alone", async (_case, role, rows) => {
    newFakeArgoCd(withData({ "policy.csv": CUSTOMER_POLICY }));

    await expect(
      primitives().list({ type: "role", context: PARSED_INSTANCE, role })
    ).resolves.toEqual(rows);
  });

  it("checks the token before reading", async () => {
    const argocd = newFakeArgoCd(installedState({ anonymousEnabled: true }));

    await expect(
      connectorError(() =>
        primitives(connectWith("not-the-token")).list({
          type: "role",
          context: PARSED_INSTANCE,
        })
      )
    ).resolves.toMatchObject({ data: { type: "insufficient_privileges" } });
    expectPhases(argocd, [[USER_INFO]]);
  });
});

describe("the held lister", () => {
  const held = (email: string, role: string, connect = connectWith()) =>
    primitives(connect).list({
      type: "held",
      context: PARSED_INSTANCE,
      email,
      role,
    });

  it("answers the role when the user holds it, P0's own line included", async () => {
    const argocd = newFakeArgoCd(
      withData({
        "policy.csv": CUSTOMER_POLICY,
        "policy.p0.csv": "g, alice@example.com, role:lead\n",
      })
    );

    await expect(held(ALICE, "role:dev")).resolves.toEqual([
      { key: "role:dev", value: "role:dev" },
    ]);
    expectPhases(argocd, [[USER_INFO], [READ_RBAC, LIST_PROJECTS]]);
  });

  it("answers nothing when they don't", async () => {
    newFakeArgoCd(withData({ "policy.csv": CUSTOMER_POLICY }));

    await expect(held(ALICE, "role:dev")).resolves.toEqual([]);
  });

  it("refuses an email the allowlist doesn't allow, before the secret is read", async () => {
    const argocd = newFakeArgoCd(installedState());
    const connect = connectWith();

    await expect(
      reasonOf(() => held("mallory@evil.io", "role:dev", connect))
    ).resolves.toBe("domain_not_allowed");
    expect(connect).not.toHaveBeenCalled();
    expect(argocd.fetch).not.toHaveBeenCalled();
  });
});
