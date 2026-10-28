import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  ARGOCD_HOST,
  connectorError,
  logger,
} from "../../../__tests__/fixtures.ts";
import { ALLOWED_EMAIL_DOMAIN_PATTERN_ENV } from "../../../allowlist.ts";
import {
  type FakeArgoCdState,
  type FakeProject,
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
import { newProjectRolePrimitives } from "../handler.ts";

const ALICE = "alice@example.com";

const PROJECTS: FakeProject[] = [
  { name: "default" },
  {
    name: "payments",
    roles: [
      { name: "deployer", groups: ["payments-team"] },
      { name: "viewer" },
      // A name Argo CD wouldn't take, which P0 never offers.
      { name: "bad name" },
    ],
  },
];

const withData = (
  data: Record<string, string>,
  projects: FakeProject[] = PROJECTS
): FakeArgoCdState =>
  installedState({ rbac: { namespace: "argocd", data }, projects });

const contextFor = (project: string, role: string) => ({
  ...PARSED_INSTANCE,
  requestId: "req-1",
  project,
  role,
});

const primitives = (connect: ConnectArgoCd = connectWith()) =>
  newProjectRolePrimitives(logger, connect);

const grant = (
  project: string,
  role: string,
  email = ALICE,
  connect: ConnectArgoCd = connectWith()
) =>
  primitives(connect).setPoliciesForUser(
    contextFor(project, role),
    email,
    userBodyOf(email),
    [{ project, role }]
  );

const revoke = (
  project: string,
  role: string,
  email = ALICE,
  connect: ConnectArgoCd = connectWith()
) =>
  primitives(connect).setPoliciesForUser(
    contextFor(project, role),
    email,
    userBodyOf(email),
    [{ project, role: null }]
  );

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

describe("a project role grant", () => {
  it("adds P0's proj line to policy.p0.csv, after the self-check, and reads it back", async () => {
    const argocd = newFakeArgoCd(withData({}));

    await grant("payments", "deployer");

    expect(argocd.state.rbac.data).toEqual({
      "policy.p0.csv": "g, alice@example.com, proj:payments:deployer\n",
    });
    expectPhases(argocd, [
      [USER_INFO],
      CAN_I,
      [READ_RBAC, LIST_PROJECTS],
      [PATCH_RBAC],
      [READ_RBAC],
    ]);
  });

  it("sends a patch that carries policy.p0.csv and nothing else", async () => {
    const argocd = newFakeArgoCd(withData({}));

    await grant("payments", "viewer");

    expect(patches(argocd)).toStrictEqual([
      {
        data: {
          "policy.p0.csv": "g, alice@example.com, proj:payments:viewer\n",
        },
      },
    ]);
    expect(postBodies(argocd).join("")).not.toContain("p0-connector");
  });

  it("succeeds without a write when P0's line is there already", async () => {
    const data = {
      "policy.p0.csv": "g, alice@example.com, proj:payments:deployer\n",
    };
    const argocd = newFakeArgoCd(withData({ ...data }));

    await grant("payments", "deployer");

    expect(argocd.state.rbac.data).toEqual(data);
    expect(patches(argocd)).toEqual([]);
  });

  it("refuses a project the account can't see", async () => {
    const argocd = newFakeArgoCd(withData({}));

    const { data } = await connectorError(() => grant("billing", "deployer"));

    expect(data).toEqual({
      type: "validation_error",
      message: `Argo CD at ${ARGOCD_HOST} has no project billing.`,
      payload: {
        host: ARGOCD_HOST,
        project: "billing",
        reason: "project_not_found",
      },
    });
    expect(patches(argocd)).toEqual([]);
  });

  it("refuses a role the project doesn't define", async () => {
    const argocd = newFakeArgoCd(withData({}));

    const { data } = await connectorError(() => grant("payments", "admin"));

    expect(data).toEqual({
      type: "validation_error",
      message: `Project payments on Argo CD at ${ARGOCD_HOST} has no role admin.`,
      payload: {
        host: ARGOCD_HOST,
        project: "payments",
        role: "admin",
        reason: "role_not_found",
      },
    });
    expect(patches(argocd)).toEqual([]);
  });

  // A role of another project's isn't this one's.
  it("refuses a role only another project defines", async () => {
    newFakeArgoCd(
      withData({}, [
        ...PROJECTS,
        { name: "billing", roles: [{ name: "admin" }] },
      ])
    );

    await expect(reasonOf(() => grant("payments", "admin"))).resolves.toBe(
      "role_not_found"
    );
  });

  describe("refuses with already_held a role the user holds", () => {
    it.each([
      [
        "through the role's groups",
        {},
        [{ name: "payments", roles: [{ name: "deployer", groups: [ALICE] }] }],
      ],
      [
        "through a customer's g line",
        { "policy.csv": "g, alice@example.com, proj:payments:deployer\n" },
        PROJECTS,
      ],
      [
        "through a role that inherits it",
        {
          "policy.csv":
            "g, role:lead, proj:payments:deployer\ng, alice@example.com, role:lead\n",
        },
        PROJECTS,
      ],
      [
        "through policy.default",
        { "policy.default": "proj:payments:deployer" },
        PROJECTS,
      ],
    ])("%s", async (_case, data, projects) => {
      const argocd = newFakeArgoCd(withData(data, projects));

      await expect(reasonOf(() => grant("payments", "deployer"))).resolves.toBe(
        "already_held"
      );
      expect(patches(argocd)).toEqual([]);
    });

    it("and names the project in what it says", async () => {
      newFakeArgoCd(
        withData({
          "policy.csv": "g, alice@example.com, proj:payments:deployer\n",
        })
      );

      const { data } = await connectorError(() =>
        grant("payments", "deployer")
      );

      expect(data).toEqual({
        type: "validation_error",
        message: `alice@example.com already holds the deployer role on project payments on Argo CD at ${ARGOCD_HOST}.`,
        payload: {
          host: ARGOCD_HOST,
          kind: "project",
          project: "payments",
          role: "deployer",
          reason: "already_held",
        },
      });
    });
  });

  it.each([
    [
      "an email in a domain the allowlist doesn't allow",
      "mallory@evil.io",
      "domain_not_allowed",
    ],
    [
      "a user that isn't an email P0 writes",
      "alice smith@example.com",
      "not_an_email",
    ],
  ])("refuses %s before the secret is read", async (_case, email, reason) => {
    const argocd = newFakeArgoCd(withData({}));
    const connect = connectWith();

    await expect(
      reasonOf(() => grant("payments", "deployer", email, connect))
    ).resolves.toBe(reason);
    expect(connect).not.toHaveBeenCalled();
    expect(argocd.fetch).not.toHaveBeenCalled();
  });

  it("refuses with self_check_failed when the account may update any project", async () => {
    const state = withData({});
    state.permissions.add("projects/update/*");
    const argocd = newFakeArgoCd(state);

    await expect(reasonOf(() => grant("payments", "deployer"))).resolves.toBe(
      "self_check_failed"
    );
    expectPhases(argocd, [[USER_INFO], CAN_I]);
  });

  it("refuses with policy_not_loaded when a line Argo CD refuses is there", async () => {
    newFakeArgoCd(withData({ "policy.csv": "nonsense\n" }));

    await expect(reasonOf(() => grant("payments", "deployer"))).resolves.toBe(
      "policy_not_loaded"
    );
  });

  it("fails with dependency_violation when the read after the patch doesn't show the line", async () => {
    const argocd = newFakeArgoCd(withData({}));
    dropPatches(argocd);

    await expect(
      connectorError(() => grant("payments", "deployer"))
    ).resolves.toMatchObject({ data: { type: "dependency_violation" } });
  });
});

describe("a project role revoke", () => {
  it("removes P0's line and leaves the rest", async () => {
    const argocd = newFakeArgoCd(
      withData({
        "policy.p0.csv":
          "g, alice@example.com, proj:payments:deployer\ng, alice@example.com, proj:payments:viewer\ng, alice@example.com, role:dev\n",
      })
    );

    await revoke("payments", "deployer");

    expect(argocd.state.rbac.data).toEqual({
      "policy.p0.csv":
        "g, alice@example.com, proj:payments:viewer\ng, alice@example.com, role:dev\n",
    });
    expect(patches(argocd)).toStrictEqual([
      {
        data: {
          "policy.p0.csv":
            "g, alice@example.com, proj:payments:viewer\ng, alice@example.com, role:dev\n",
        },
      },
    ]);
    expectPhases(argocd, [[USER_INFO], [READ_RBAC], [PATCH_RBAC], [READ_RBAC]]);
  });

  it("succeeds without a write when the line isn't there", async () => {
    const argocd = newFakeArgoCd(withData({}));

    await revoke("payments", "deployer");

    expect(patches(argocd)).toEqual([]);
  });

  // The project may have gone since the grant: the line still goes.
  it("removes the line of a project that no longer exists, without asking about projects", async () => {
    const argocd = newFakeArgoCd(
      withData(
        { "policy.p0.csv": "g, alice@example.com, proj:payments:deployer\n" },
        []
      )
    );

    await revoke("payments", "deployer");

    expect(argocd.state.rbac.data?.["policy.p0.csv"]).toBe("");
    expect(argocd.calls().some((call) => call.includes("projects"))).toBe(
      false
    );
  });

  it("checks neither the allowlist nor the account's privileges", async () => {
    vi.stubEnv(ALLOWED_EMAIL_DOMAIN_PATTERN_ENV, "");
    const state = withData({
      "policy.p0.csv": "g, alice@example.com, proj:payments:deployer\n",
    });
    state.permissions.add("clusters/update/*");
    const argocd = newFakeArgoCd(state);

    await revoke("payments", "deployer");

    expect(argocd.state.rbac.data?.["policy.p0.csv"]).toBe("");
    expect(argocd.calls().some((call) => call.includes("can-i"))).toBe(false);
  });
});

describe("setPoliciesForUser", () => {
  it.each([
    ["no policy", []],
    [
      "two policies",
      [
        { project: "payments", role: "deployer" },
        { project: "payments", role: null },
      ],
    ],
    ["a policy for another project", [{ project: "billing", role: null }]],
    ["a grant of another role", [{ project: "payments", role: "viewer" }]],
  ])("refuses %s as P0's bug", async (_case, policies) => {
    const argocd = newFakeArgoCd(withData({}));

    const { data } = await connectorError(() =>
      primitives().setPoliciesForUser(
        contextFor("payments", "deployer"),
        ALICE,
        userBodyOf(ALICE),
        policies
      )
    );

    expect(data.type).toBe("unknown");
    expect(argocd.fetch).not.toHaveBeenCalled();
  });

  it.each([
    [
      "no policy",
      [],
      "Expected exactly 1 policy for an Argo CD project role, got 0",
      { nPolicies: 0 },
    ],
    [
      "a policy for another project",
      [{ project: "billing", role: null }],
      "P0 asked the Argo CD connector to set a project role other than the request's.",
      {},
    ],
  ])(
    "says what P0 got wrong for %s",
    async (_case, policies, message, extra) => {
      newFakeArgoCd(withData({}));

      const { data } = await connectorError(() =>
        primitives().setPoliciesForUser(
          contextFor("payments", "deployer"),
          ALICE,
          userBodyOf(ALICE),
          policies
        )
      );

      expect(data).toEqual({
        type: "unknown",
        message,
        payload: { requestId: "req-1", ...extra },
      });
    }
  );

  it("refuses a project P0 couldn't write as a role the instance hasn't", async () => {
    const argocd = newFakeArgoCd(withData({}));

    await expect(reasonOf(() => grant("Payments", "deployer"))).resolves.toBe(
      "role_not_found"
    );
    expect(argocd.fetch).not.toHaveBeenCalled();
  });

  it("refuses to create a user, as P0's bug", async () => {
    const { data } = await connectorError(() =>
      primitives().createUser(contextFor("payments", "deployer"), {
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

describe("the listers", () => {
  it("list the projects the account can see", async () => {
    const argocd = newFakeArgoCd(withData({}));

    await expect(
      primitives().list({ type: "project", context: PARSED_INSTANCE })
    ).resolves.toEqual([
      { key: "default", value: "default" },
      { key: "payments", value: "payments" },
    ]);
    expectPhases(argocd, [[USER_INFO], [READ_RBAC, LIST_PROJECTS]]);
  });

  it.each([
    ["one it can see", "payments", [{ key: "payments", value: "payments" }]],
    ["one it can't", "billing", []],
  ])("answer for %s project alone", async (_case, project, rows) => {
    newFakeArgoCd(withData({}));

    await expect(
      primitives().list({ type: "project", context: PARSED_INSTANCE, project })
    ).resolves.toEqual(rows);
  });

  it("list a project's roles, less any P0 couldn't write", async () => {
    newFakeArgoCd(withData({}));

    await expect(
      primitives().list({
        type: "role",
        context: PARSED_INSTANCE,
        project: "payments",
      })
    ).resolves.toEqual([
      { key: "deployer", value: "deployer" },
      { key: "viewer", value: "viewer" },
    ]);
  });

  it.each([
    [
      "a role of the project's",
      "payments",
      "viewer",
      [{ key: "viewer", value: "viewer" }],
    ],
    ["a role it doesn't define", "payments", "admin", []],
    ["a project it can't see", "billing", "viewer", []],
    ["a project it can't see, with no role", "billing", undefined, []],
  ])("answer for %s alone", async (_case, project, role, rows) => {
    newFakeArgoCd(withData({}));

    await expect(
      primitives().list({
        type: "role",
        context: PARSED_INSTANCE,
        project,
        role,
      })
    ).resolves.toEqual(rows);
  });

  it("say whether the user holds the project role", async () => {
    newFakeArgoCd(
      withData({}, [
        { name: "payments", roles: [{ name: "deployer", groups: [ALICE] }] },
      ])
    );
    const held = (email: string) =>
      primitives().list({
        type: "held",
        context: PARSED_INSTANCE,
        email,
        project: "payments",
        role: "deployer",
      });

    await expect(held(ALICE)).resolves.toEqual([
      { key: "deployer", value: "deployer" },
    ]);
    await expect(held("bob@example.com")).resolves.toEqual([]);
  });

  it("refuse a held query for an email the allowlist doesn't allow, before the secret is read", async () => {
    const argocd = newFakeArgoCd(withData({}));
    const connect = connectWith();

    await expect(
      reasonOf(() =>
        primitives(connect).list({
          type: "held",
          context: PARSED_INSTANCE,
          email: "mallory@evil.io",
          project: "payments",
          role: "deployer",
        })
      )
    ).resolves.toBe("domain_not_allowed");
    expect(connect).not.toHaveBeenCalled();
    expect(argocd.fetch).not.toHaveBeenCalled();
  });
});
