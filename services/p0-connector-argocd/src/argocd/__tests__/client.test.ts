import { ConnectorError } from "@p0security/connector-core";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { INSTANCE, TOKEN, logger } from "../../__tests__/fixtures.ts";
import { instance } from "../../instance.ts";
import { readApiToken } from "../../secrets.ts";
import { ArgoCdError } from "../api.ts";
import {
  P0_POLICY_KEY,
  type RbacPatch,
  argoCdClientFor,
  connectArgoCd,
  rbacTargetOf,
} from "../client.ts";
import {
  ARGOCD_ORIGIN,
  BEARER,
  type FakeArgoCdState,
  installedState,
  newFakeArgoCd,
  rbacResource,
  sentPatch,
} from "./fake-argocd.ts";

vi.mock("../../secrets.ts");

const TARGET = { app: "argocd", namespace: "argocd" };

const client = (token = TOKEN) =>
  argoCdClientFor({ url: ARGOCD_ORIGIN, token, logger });

/** The {@link ArgoCdError} `run` fails with. Anything else fails the test. */
const argoCdError = async (run: () => Promise<unknown>) => {
  const outcome = await run().then(
    () => new Error("expected the call to throw"),
    (error: unknown) => error
  );
  if (outcome instanceof ArgoCdError) return outcome;
  throw outcome;
};

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status });

const stubFetch = (answer: () => Response) => {
  const mock = vi.fn(async () => answer());
  vi.stubGlobal("fetch", mock);
  return mock;
};

beforeEach(() => {
  vi.clearAllMocks();
});

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe("connectArgoCd", () => {
  it("reads the token on every connect, and calls the instance with it", async () => {
    vi.mocked(readApiToken).mockResolvedValue(TOKEN);
    const argocd = newFakeArgoCd(installedState());
    const parsed = instance.parse(INSTANCE);

    await (await connectArgoCd(parsed, logger)).userInfo();
    await (await connectArgoCd(parsed, logger)).userInfo();

    expect(readApiToken).toHaveBeenCalledTimes(2);
    expect(readApiToken).toHaveBeenCalledWith(parsed.secret, logger);
    for (const [url, init] of argocd.fetch.mock.calls) {
      expect(url.startsWith(`${ARGOCD_ORIGIN}/api/v1/`)).toBe(true);
      expect(new Headers(init?.headers).get("authorization")).toBe(BEARER);
    }
  });

  it("fails as the token read does, before any call", async () => {
    const refused = new ConnectorError({
      type: "insufficient_privileges",
      message: "no",
      payload: {},
    });
    vi.mocked(readApiToken).mockRejectedValue(refused);
    const argocd = newFakeArgoCd(installedState());

    await expect(connectArgoCd(instance.parse(INSTANCE), logger)).rejects.toBe(
      refused
    );
    expect(argocd.fetch).not.toHaveBeenCalled();
  });
});

describe("rbacTargetOf", () => {
  it("is the managing Application's name and the namespace", () => {
    expect(
      rbacTargetOf(
        instance.parse({
          ...INSTANCE,
          managingApp: "platform/argo-cd",
          namespace: "gitops",
        })
      )
    ).toEqual({ app: "argo-cd", namespace: "gitops" });
  });
});

describe("version", () => {
  it("is Argo CD's Version, from outside /api/v1", async () => {
    const argocd = newFakeArgoCd(
      installedState({ version: "v3.1.0-rc1+8d1e2a0" })
    );

    await expect(client().version()).resolves.toBe("v3.1.0-rc1+8d1e2a0");
    expect(argocd.calls()).toEqual([`GET ${ARGOCD_ORIGIN}/api/version`]);
  });

  it("is told to a token Argo CD doesn't accept too", async () => {
    newFakeArgoCd(installedState());

    await expect(client("not-the-token").version()).resolves.toBe(
      "v3.5.5+2f9b0d1"
    );
  });

  it.each([{}, { Version: "" }, { Version: 3 }])(
    "fails on %j",
    async (body) => {
      stubFetch(() => json(body));

      const error = await argoCdError(() => client().version());

      expect(error.failure).toEqual({
        kind: "unexpected",
        reason: "wrong_shape",
      });
    }
  );
});

describe("userInfo", () => {
  it("is the account the token belongs to", async () => {
    newFakeArgoCd(installedState());

    await expect(client().userInfo()).resolves.toEqual({
      username: "p0-connector",
      issuer: "argocd",
    });
  });

  it.each([false, true])(
    "fails as anonymous for a token Argo CD doesn't accept (anonymous access on: %s)",
    async (anonymousEnabled) => {
      newFakeArgoCd(installedState({ anonymousEnabled }));

      const error = await argoCdError(() => client("not-the-token").userInfo());

      expect(error.failure).toEqual({ kind: "anonymous" });
      expect(error.call.route).toBe("/api/v1/session/userinfo");
    }
  );

  it.each([{}, { loggedIn: false }, { groups: [] }])(
    "fails as anonymous on %j",
    async (body) => {
      stubFetch(() => json(body));

      const error = await argoCdError(() => client().userInfo());

      expect(error.failure).toEqual({ kind: "anonymous" });
    }
  );

  it("takes an issuer the gateway left out as empty", async () => {
    stubFetch(() => json({ loggedIn: true, username: "p0-connector" }));

    await expect(client().userInfo()).resolves.toEqual({
      username: "p0-connector",
      issuer: "",
    });
  });

  it("fails with the status when Argo CD answers 401", async () => {
    stubFetch(() => json({ code: 16 }, 401));

    const error = await argoCdError(() => client().userInfo());

    expect(error.failure).toEqual({ kind: "status", status: 401 });
  });

  it.each([
    { loggedIn: true },
    { loggedIn: true, username: "" },
    { loggedIn: "yes" },
  ])("fails on %j", async (body) => {
    stubFetch(() => json(body));

    const error = await argoCdError(() => client().userInfo());

    expect(error.failure).toEqual({
      kind: "unexpected",
      reason: "wrong_shape",
    });
  });
});

describe("canI", () => {
  const state = (): FakeArgoCdState =>
    installedState({
      permissions: new Set([
        ...installedState().permissions,
        "clusters/update/*",
        "applications/sync/*/*",
      ]),
    });

  it.each<[string, string, string, boolean]>([
    ["applications", "sync", "*/*", true],
    ["clusters", "update", "*", true],
    ["applications", "delete", "*/*", false],
    ["accounts", "update", "*", false],
    ["projects", "get", "*", true],
  ])("asks whether it may %s %s %s", async (resource, action, object, yes) => {
    newFakeArgoCd(state());

    await expect(client().canI(resource, action, object)).resolves.toBe(yes);
  });

  it("sends the object's slashes as slashes", async () => {
    const argocd = newFakeArgoCd(state());

    await client().canI("applications", "sync", "*/*");

    expect(argocd.calls()).toEqual([
      `GET ${ARGOCD_ORIGIN}/api/v1/account/can-i/applications/sync/*/*`,
    ]);
  });

  it("is refused a part that would change the path", async () => {
    const argocd = newFakeArgoCd(state());

    await expect(client().canI("..", "sync", "*/*")).rejects.toBeInstanceOf(
      ConnectorError
    );
    await expect(
      client().canI("applications", "sync", "a//b")
    ).rejects.toBeInstanceOf(ConnectorError);
    expect(argocd.fetch).not.toHaveBeenCalled();
  });

  it.each([{}, { value: "maybe" }, { value: true }, { value: "YES" }])(
    "fails on %j",
    async (body) => {
      stubFetch(() => json(body));

      const error = await argoCdError(() =>
        client().canI("applications", "sync", "*/*")
      );

      expect(error.failure).toEqual({
        kind: "unexpected",
        reason: "wrong_shape",
      });
    }
  );
});

describe("getApplication", () => {
  it("is the Application's project and what it manages", async () => {
    const argocd = newFakeArgoCd(installedState());

    await expect(client().getApplication("argocd")).resolves.toEqual({
      project: "platform",
      resources: [
        {
          group: "apps",
          version: "v1",
          kind: "Deployment",
          namespace: "argocd",
          name: "argocd-server",
        },
        { group: "", ...rbacResource() },
      ],
    });
    expect(argocd.calls()).toEqual([
      `GET ${ARGOCD_ORIGIN}/api/v1/applications/argocd`,
    ]);
  });

  // The gateway leaves out an empty string: the core group, and the
  // namespace of a cluster-scoped resource.
  it("reads a resource's left-out fields as empty", async () => {
    stubFetch(() =>
      json({
        spec: { project: "platform" },
        status: { resources: [{ kind: "Namespace", name: "argocd" }] },
      })
    );

    await expect(client().getApplication("argocd")).resolves.toEqual({
      project: "platform",
      resources: [
        {
          group: "",
          version: "",
          kind: "Namespace",
          namespace: "",
          name: "argocd",
        },
      ],
    });
  });

  it("reads an Application with no status as managing nothing", async () => {
    stubFetch(() => json({ spec: { project: "platform" } }));

    await expect(client().getApplication("argocd")).resolves.toEqual({
      project: "platform",
      resources: [],
    });
  });

  it("reads a null resource list as empty", async () => {
    stubFetch(() =>
      json({ spec: { project: "platform" }, status: { resources: null } })
    );

    await expect(client().getApplication("argocd")).resolves.toEqual({
      project: "platform",
      resources: [],
    });
  });

  // Argo CD doesn't say whether an Application exists to a caller who may
  // not read it.
  it.each([
    ["doesn't exist", "nope", installedState()],
    [
      "may not be read",
      "argocd",
      installedState({ permissions: new Set(["projects/get/*"]) }),
    ],
  ])("fails with a 403 when the Application %s", async (_case, app, state) => {
    newFakeArgoCd(state);

    const error = await argoCdError(() => client().getApplication(app));

    expect(error.failure).toEqual({ kind: "status", status: 403 });
    expect(error.call.permission).toBe("applications, get");
  });
});

describe("readRbacConfigMap", () => {
  it("reads argocd-rbac-cm's keys through the managing Application", async () => {
    const argocd = newFakeArgoCd(installedState());

    await expect(client().readRbacConfigMap(TARGET)).resolves.toEqual({
      data: { "policy.csv": "p, role:dev, applications, get, */*, allow\n" },
    });
    expect(argocd.calls()).toEqual([
      `GET ${ARGOCD_ORIGIN}/api/v1/applications/argocd/resource?namespace=argocd&resourceName=argocd-rbac-cm&version=v1&kind=ConfigMap&group=`,
    ]);
  });

  it("reads a ConfigMap with no data as no keys", async () => {
    newFakeArgoCd(installedState({ rbac: { namespace: "argocd" } }));

    await expect(client().readRbacConfigMap(TARGET)).resolves.toEqual({
      data: {},
    });
  });

  it("fails with not_managed when the Application doesn't manage it there", async () => {
    newFakeArgoCd(installedState());

    const error = await argoCdError(() =>
      client().readRbacConfigMap({ app: "argocd", namespace: "elsewhere" })
    );

    expect(error.failure).toEqual({
      kind: "not_managed",
      app: "argocd",
      namespace: "elsewhere",
    });
    expect(error.call.route).toBe("/api/v1/applications/{name}/resource");
  });

  it("refuses an Application name that would change the path, before any call", async () => {
    const argocd = newFakeArgoCd(installedState());

    for (const app of ["..", "."]) {
      await expect(
        client().readRbacConfigMap({ app, namespace: "argocd" })
      ).rejects.toBeInstanceOf(ConnectorError);
      await expect(
        client().patchRbacConfigMap({ app, namespace: "argocd" }, {})
      ).rejects.toBeInstanceOf(ConnectorError);
    }
    expect(argocd.fetch).not.toHaveBeenCalled();
  });

  it("fails with a 403 when the Application isn't there", async () => {
    newFakeArgoCd(installedState());

    const error = await argoCdError(() =>
      client().readRbacConfigMap({ app: "nope", namespace: "argocd" })
    );

    expect(error.failure).toEqual({ kind: "status", status: 403 });
  });

  const manifest = (object: unknown) =>
    json({
      manifest: typeof object === "string" ? object : JSON.stringify(object),
    });
  const CM = {
    apiVersion: "v1",
    kind: "ConfigMap",
    metadata: { name: "argocd-rbac-cm", namespace: "argocd" },
    data: { a: "b" },
  };

  it.each<[string, unknown, string]>([
    ["isn't JSON", "{", "not_json"],
    ["isn't a ConfigMap", { ...CM, kind: "Secret" }, "wrong_shape"],
    ["isn't v1", { ...CM, apiVersion: "v2" }, "wrong_shape"],
    [
      "is another ConfigMap",
      { ...CM, metadata: { ...CM.metadata, name: "argocd-cm" } },
      "wrong_shape",
    ],
    [
      "is in another namespace",
      { ...CM, metadata: { ...CM.metadata, namespace: "other" } },
      "wrong_shape",
    ],
    [
      "has a value that isn't a string",
      { ...CM, data: { a: 1 } },
      "wrong_shape",
    ],
  ])("fails when the manifest %s", async (_case, object, reason) => {
    stubFetch(() => manifest(object));

    const error = await argoCdError(() => client().readRbacConfigMap(TARGET));

    expect(error.failure).toEqual({ kind: "unexpected", reason });
  });

  it("fails when there's no manifest", async () => {
    stubFetch(() => json({}));

    const error = await argoCdError(() => client().readRbacConfigMap(TARGET));

    expect(error.failure).toEqual({
      kind: "unexpected",
      reason: "wrong_shape",
    });
  });
});

describe("patchRbacConfigMap", () => {
  it("merges the P0 key into argocd-rbac-cm, leaving the rest", async () => {
    const argocd = newFakeArgoCd(installedState());
    const csv = "g, someone@example.com, role:readonly\n";

    await client().patchRbacConfigMap(TARGET, { [P0_POLICY_KEY]: csv });

    expect(argocd.state.rbac.data).toEqual({
      "policy.csv": "p, role:dev, applications, get, */*, allow\n",
      [P0_POLICY_KEY]: csv,
    });
    expect(argocd.calls()).toEqual([
      `POST ${ARGOCD_ORIGIN}/api/v1/applications/argocd/resource?namespace=argocd&resourceName=argocd-rbac-cm&version=v1&kind=ConfigMap&group=&patchType=application%2Fmerge-patch%2Bjson`,
    ]);
  });

  it("sends the patch as a JSON string, once", async () => {
    const argocd = newFakeArgoCd(installedState());

    await client().patchRbacConfigMap(TARGET, { [P0_POLICY_KEY]: "x\n" });

    const init = argocd.fetch.mock.calls[0]?.[1];
    expect(init?.body).toBe(
      JSON.stringify(JSON.stringify({ data: { [P0_POLICY_KEY]: "x\n" } }))
    );
    expect(sentPatch(init)).toEqual({ data: { [P0_POLICY_KEY]: "x\n" } });
  });

  it("sends an empty patch, which changes nothing", async () => {
    const argocd = newFakeArgoCd(installedState());
    const before = { ...argocd.state.rbac.data };

    await client().patchRbacConfigMap(TARGET, {});

    expect(sentPatch(argocd.fetch.mock.calls[0]?.[1])).toEqual({ data: {} });
    expect(argocd.state.rbac.data).toEqual(before);
  });

  it.each([
    { "policy.csv": "p, x" },
    { "policy.default": "role:admin" },
    { [P0_POLICY_KEY]: "x", "policy.csv": "" },
  ])("refuses to write any other key, before any call: %j", async (patch) => {
    const argocd = newFakeArgoCd(installedState());
    const data = { ...argocd.state.rbac.data };

    await expect(
      client().patchRbacConfigMap(TARGET, patch as RbacPatch)
    ).rejects.toThrow(/policy\.p0\.csv only/);
    expect(argocd.fetch).not.toHaveBeenCalled();
    expect(argocd.state.rbac.data).toEqual(data);
  });

  // Argo CD checks the update permission first: the fine-grained one names
  // the namespace, so it takes a plain `update` to get as far as the lookup.
  it("fails with not_managed when the Application doesn't manage it there", async () => {
    newFakeArgoCd(
      installedState({
        permissions: new Set(["applications/update/platform/argocd"]),
      })
    );

    const error = await argoCdError(() =>
      client().patchRbacConfigMap({ app: "argocd", namespace: "elsewhere" }, {})
    );

    expect(error.failure).toEqual({
      kind: "not_managed",
      app: "argocd",
      namespace: "elsewhere",
    });
    expect(error.call.method).toBe("POST");
  });

  it("needs only update, not get, to patch", async () => {
    const argocd = newFakeArgoCd(
      installedState({
        permissions: new Set([
          "applications/update//ConfigMap/argocd/argocd-rbac-cm/platform/argocd",
        ]),
      })
    );

    await client().patchRbacConfigMap(TARGET, { [P0_POLICY_KEY]: "x\n" });

    expect(argocd.state.rbac.data?.[P0_POLICY_KEY]).toBe("x\n");
  });

  it("fails with a 403 when the account may not update argocd-rbac-cm", async () => {
    const argocd = newFakeArgoCd(
      installedState({
        permissions: new Set(["applications/get/platform/argocd"]),
      })
    );

    const error = await argoCdError(() =>
      client().patchRbacConfigMap(TARGET, { [P0_POLICY_KEY]: "x" })
    );

    expect(error.failure).toEqual({ kind: "status", status: 403 });
    expect(error.call.permission).toBe(
      "applications, update//ConfigMap/argocd/argocd-rbac-cm"
    );
    expect(argocd.state.rbac.data?.[P0_POLICY_KEY]).toBeUndefined();
  });

  it("passes on any other failure as it is", async () => {
    stubFetch(() => json({}, 500));

    const error = await argoCdError(() =>
      client().patchRbacConfigMap(TARGET, {})
    );

    expect(error.failure).toEqual({ kind: "status", status: 500 });
  });
});

describe("listProjects", () => {
  it("is each project the account may see, with its roles and their groups", async () => {
    const argocd = newFakeArgoCd(installedState());

    await expect(client().listProjects()).resolves.toEqual([
      { name: "default", roles: [] },
      {
        name: "payments",
        roles: [{ name: "deployer", groups: ["payments-team"] }],
      },
    ]);
    expect(argocd.calls()).toEqual([`GET ${ARGOCD_ORIGIN}/api/v1/projects`]);
  });

  it("is empty when the account may see none, which Argo CD sends as null", async () => {
    newFakeArgoCd(
      installedState({
        permissions: new Set(["applications/get/platform/argocd"]),
      })
    );

    await expect(client().listProjects()).resolves.toEqual([]);
  });

  it("reads a role with no groups as bound to none", async () => {
    stubFetch(() =>
      json({
        items: [
          { metadata: { name: "a" }, spec: { roles: [{ name: "r" }] } },
          {
            metadata: { name: "b" },
            spec: { roles: [{ name: "s", groups: null }] },
          },
        ],
      })
    );

    await expect(client().listProjects()).resolves.toEqual([
      { name: "a", roles: [{ name: "r", groups: [] }] },
      { name: "b", roles: [{ name: "s", groups: [] }] },
    ]);
  });

  it.each([
    { items: [{ metadata: {}, spec: {} }] },
    { items: [{ metadata: { name: "a" } }] },
    { items: [{ metadata: { name: "a" }, spec: { roles: [{}] } }] },
    { items: {} },
  ])("fails on %j", async (body) => {
    stubFetch(() => json(body));

    const error = await argoCdError(() => client().listProjects());

    expect(error.failure).toEqual({
      kind: "unexpected",
      reason: "wrong_shape",
    });
  });
});

describe("a token Argo CD doesn't accept", () => {
  it("is a 401 on the routes that need one", async () => {
    newFakeArgoCd(installedState());

    for (const run of [
      () => client("not-the-token").canI("applications", "sync", "*/*"),
      () => client("not-the-token").listProjects(),
      () => client("not-the-token").readRbacConfigMap(TARGET),
    ]) {
      const error = await argoCdError(run);
      expect(error.failure).toEqual({ kind: "status", status: 401 });
    }
  });
});
