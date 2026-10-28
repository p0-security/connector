/**
 * An Argo CD double for the client's tests and the handlers' to come. It
 * copies what Argo CD's API server does (read from the v3.5.5 source, not
 * checked on a live instance), or the tests prove nothing:
 *
 * - every `/api/v1` call wants `Authorization: Bearer <token>`. One it
 *   doesn't accept is a 401, unless anonymous access is on
 *   (`users.anonymous.enabled`), when it is an anonymous caller instead;
 * - `GET /api/version` answers anyone, an anonymous caller with `Version`
 *   only;
 * - `GET /api/v1/session/userinfo` answers anyone, and `{}` for a token it
 *   doesn't accept: the session service skips authentication, and the
 *   gateway's encoding/json leaves out the `omitempty` `loggedIn: false`;
 * - `can-i` answers the caller about itself, `{"value":"yes"}` or
 *   `{"value":"no"}`. Its last part is a `**` path, slashes and all: an
 *   object whose slash was sent as `%2F` isn't the same object, and is
 *   answered `no`;
 * - an Application that doesn't exist is answered 403, as one the caller may
 *   not read is, so the existence of an Application isn't leaked (when the
 *   call names no `project`, as the connector's don't);
 * - `GET .../resource` answers `{"manifest": "<the live object as a JSON
 *   string>"}`, and 400 (InvalidArgument) for a resource the Application
 *   doesn't manage, after the RBAC check;
 * - `POST .../resource` needs `update` on the Application, or v3's
 *   fine-grained `update/<group>/<kind>/<namespace>/<name>`, and not `get`;
 * - `POST .../resource` takes the patch as a JSON string: the HTTP body is a
 *   JSON string literal, and a JSON object is a 400, since grpc-gateway
 *   unmarshals the body into the request's string `patch` field;
 * - `GET /api/v1/projects` lists the projects the caller may get, with
 *   `items: null` when there are none (the list's `items` has no
 *   `omitempty`);
 * - errors are grpc-gateway's `{"error", "code", "message"}`.
 */
import { vi } from "vitest";

import { TOKEN } from "../../__tests__/fixtures.ts";

export const ARGOCD_ORIGIN = "https://argocd.example.com";

/** The header the connector sends with {@link TOKEN}. */
export const BEARER = `Bearer ${TOKEN}`;

export const RBAC_CM = "argocd-rbac-cm";

/** A resource an Application manages, as its `status.resources` lists it. */
export type FakeResource = {
  group?: string;
  version: string;
  kind: string;
  namespace?: string;
  name: string;
};

export type FakeApplication = {
  name: string;
  project: string;
  resources: FakeResource[];
};

export type FakeProject = {
  name: string;
  roles?: { name: string; groups?: string[]; policies?: string[] }[];
};

export type FakeArgoCdState = {
  /** `Version`, as `/api/version` gives it. */
  version?: string;
  /** Whether a token Argo CD doesn't accept is an anonymous caller. */
  anonymousEnabled?: boolean;
  /**
   * What the caller may do, as `<resource>/<action>/<object>`: `can-i`
   * answers yes for exactly these, and the routes check the ones they need.
   * The connector's `applications/get/<project>/<app>`, say. A `*` object
   * stands for any.
   */
  permissions: Set<string>;
  /** What an anonymous caller may do, in the same form. */
  anonymousPermissions?: Set<string>;
  applications: FakeApplication[];
  /** `argocd-rbac-cm`, and the namespace it is in. */
  rbac: { namespace: string; data?: Record<string, string> };
  projects: FakeProject[];
};

/** The double, its state, and the `fetch` it stands in for. */
export type FakeArgoCd = ReturnType<typeof newFakeArgoCd>;

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });

// grpc-gateway's error body: the gRPC code and its message.
const grpcError = (status: number, code: number, message: string) =>
  json({ error: message, code, message }, status);

const unauthenticated = () =>
  grpcError(401, 16, "invalid session: token signature is invalid");
const permissionDenied = () => grpcError(403, 7, "permission denied");
const notFound = (message: string) => grpcError(404, 5, message);
const invalid = (message: string) => grpcError(400, 3, message);

/** The patch string a call sent: the HTTP body, which is a JSON string. */
export const sentPatch = (init?: RequestInit): unknown => {
  if (typeof init?.body !== "string") throw new Error("no body");
  const patch: unknown = JSON.parse(init.body);
  if (typeof patch !== "string") throw new Error("the body isn't a string");
  return JSON.parse(patch);
};

/** A JSON merge patch (RFC 7386) of a string map: `null` removes a key. */
const mergeData = (
  data: Record<string, string>,
  patch: Record<string, unknown>
): Record<string, string> | undefined => {
  const merged = { ...data };
  for (const [key, value] of Object.entries(patch)) {
    if (value === null) delete merged[key];
    else if (typeof value === "string") merged[key] = value;
    // Kubernetes refuses a ConfigMap value that isn't a string.
    else return undefined;
  }
  return merged;
};

export const newFakeArgoCd = (state: FakeArgoCdState) => {
  const answer = async (
    input: string,
    init: RequestInit = {}
  ): Promise<Response> => {
    const url = new URL(input);
    const method = init.method ?? "GET";
    const authorized =
      new Headers(init.headers).get("authorization") === BEARER;
    const anonymous = !authorized && state.anonymousEnabled === true;
    const granted = authorized
      ? state.permissions
      : (state.anonymousPermissions ?? new Set<string>());
    const may = (resource: string, action: string, object: string) =>
      granted.has(`${resource}/${action}/${object}`) ||
      granted.has(`${resource}/${action}/*`);
    const path = url.pathname;
    const query = url.searchParams;

    if (path === "/api/version" && method === "GET") {
      const version = state.version ?? "v3.5.5+2f9b0d1";
      return json(
        authorized || anonymous
          ? { Version: version, GoVersion: "go1.25.1", Platform: "linux/amd64" }
          : { Version: version }
      );
    }

    if (path === "/api/v1/session/userinfo" && method === "GET") {
      return json(
        authorized
          ? { loggedIn: true, username: "p0-connector", iss: "argocd" }
          : // Go's encoding/json leaves out an `omitempty` false and "".
            {}
      );
    }

    if (!path.startsWith("/api/v1/")) return notFound("Not Found");
    if (!authorized && !anonymous) return unauthenticated();

    // The path's `**` part as it was sent, so a `%2F` stays one.
    const canI = /^\/api\/v1\/account\/can-i\/([^/]+)\/([^/]+)\/(.+)$/.exec(
      path
    );
    if (canI && method === "GET") {
      const [, resource = "", action = "", object = ""] = canI;
      const value =
        !object.includes("%2F") &&
        granted.has(
          `${decodeURIComponent(resource)}/${decodeURIComponent(action)}/${decodeURIComponent(object)}`
        );
      return json({ value: value ? "yes" : "no" });
    }

    if (path === "/api/v1/projects" && method === "GET") {
      const items = state.projects
        .filter(({ name }) => may("projects", "get", name))
        .map(({ name, roles }) => ({
          metadata: { name, namespace: "argocd", uid: `uid-${name}` },
          spec: {
            description: `the ${name} project`,
            sourceRepos: ["*"],
            ...(roles === undefined ? {} : { roles }),
          },
          status: {},
        }));
      return json({
        metadata: { resourceVersion: "4242" },
        items: items.length > 0 ? items : null,
      });
    }

    const app = /^\/api\/v1\/applications\/([^/]+)(\/resource)?$/.exec(path);
    if (app) {
      const name = decodeURIComponent(app[1] ?? "");
      const found = state.applications.find((a) => a.name === name);
      const object = found ? `${found.project}/${found.name}` : "";
      const resource = {
        group: query.get("group") ?? "",
        version: query.get("version") ?? "",
        kind: query.get("kind") ?? "",
        namespace: query.get("namespace") ?? "",
        name: query.get("resourceName") ?? "",
      };
      // A write needs `update` on the Application, or v3's fine-grained
      // `update/<group>/<kind>/<namespace>/<name>` on it, named by the query.
      // A read needs `get`.
      const allowed =
        method === "POST"
          ? may("applications", "update", object) ||
            may(
              "applications",
              `update/${resource.group}/${resource.kind}/${resource.namespace}/${resource.name}`,
              object
            )
          : may("applications", "get", object);
      // Argo CD checks RBAC on the Application it found, and answers one it
      // didn't find the same way as one the caller may not read.
      if (!found || !allowed) return permissionDenied();

      if (app[2] === undefined && method === "GET") {
        return json({
          metadata: { name, namespace: "argocd", resourceVersion: "77" },
          spec: {
            project: found.project,
            source: { repoURL: "https://git.example.com/infra", path: "." },
            destination: { server: "https://kubernetes.default.svc" },
          },
          status: {
            resources: found.resources.map((resource) => ({
              ...resource,
              status: "Synced",
            })),
            sync: { status: "Synced" },
            health: { status: "Healthy" },
          },
        });
      }

      if (app[2] === undefined) return notFound("Not Found");
      const managed = found.resources.some(
        (r) =>
          (r.group ?? "") === resource.group &&
          r.version === resource.version &&
          r.kind === resource.kind &&
          (r.namespace ?? "") === resource.namespace &&
          r.name === resource.name
      );
      const isRbac =
        resource.group === "" &&
        resource.version === "v1" &&
        resource.kind === "ConfigMap" &&
        resource.name === RBAC_CM &&
        resource.namespace === state.rbac.namespace;
      // getAppLiveResource's InvalidArgument, after the RBAC check.
      if (!managed || !isRbac) {
        return invalid(
          `${resource.kind} ${resource.group} ${resource.name} not found as part of application ${name}`
        );
      }

      if (method === "GET") {
        const manifest = {
          apiVersion: "v1",
          kind: "ConfigMap",
          metadata: {
            name: RBAC_CM,
            namespace: state.rbac.namespace,
            resourceVersion: "1234",
            labels: { "app.kubernetes.io/part-of": "argocd" },
          },
          ...(state.rbac.data === undefined ? {} : { data: state.rbac.data }),
        };
        return json({ manifest: JSON.stringify(manifest) });
      }

      if (method === "POST") {
        if (query.get("patchType") !== "application/merge-patch+json") {
          return invalid(
            `Patch type '${query.get("patchType")}' is not supported`
          );
        }
        let patch: unknown;
        try {
          const body: unknown = JSON.parse(
            typeof init.body === "string" ? init.body : ""
          );
          if (typeof body !== "string") {
            return invalid(
              "json: cannot unmarshal object into Go value of type string"
            );
          }
          patch = JSON.parse(body);
        } catch {
          return invalid("invalid character in patch");
        }
        if (typeof patch !== "object" || patch === null) {
          return invalid("patch isn't a JSON object");
        }
        const { data } = patch as { data?: unknown };
        if (data !== undefined) {
          if (typeof data !== "object" || data === null) {
            return invalid("data isn't an object");
          }
          const merged = mergeData(
            state.rbac.data ?? {},
            data as Record<string, unknown>
          );
          if (!merged) return invalid("a ConfigMap value must be a string");
          state.rbac.data = merged;
        }
        return json({ manifest: "{}" });
      }
    }

    return notFound("Not Found");
  };

  const fetchMock = vi.fn(answer);
  vi.stubGlobal("fetch", fetchMock);
  return {
    state,
    fetch: fetchMock,
    /** Each call's method and URL. */
    calls: () =>
      fetchMock.mock.calls.map(
        ([url, init]) => `${init?.method ?? "GET"} ${url}`
      ),
  };
};

/** The resource `argocd-rbac-cm` is, as an Application lists it. */
export const rbacResource = (namespace = "argocd"): FakeResource => ({
  version: "v1",
  kind: "ConfigMap",
  namespace,
  name: RBAC_CM,
});

/**
 * A state where everything is as the install steps leave it: `platform/argocd`
 * manages `argocd-rbac-cm`, and the account holds exactly the connector's
 * three policy lines.
 */
export const installedState = (
  overrides: Partial<FakeArgoCdState> = {}
): FakeArgoCdState => ({
  permissions: new Set([
    "applications/get/platform/argocd",
    "applications/update//ConfigMap/argocd/argocd-rbac-cm/platform/argocd",
    "projects/get/*",
  ]),
  applications: [
    {
      name: "argocd",
      project: "platform",
      resources: [
        {
          group: "apps",
          version: "v1",
          kind: "Deployment",
          namespace: "argocd",
          name: "argocd-server",
        },
        rbacResource(),
      ],
    },
  ],
  rbac: {
    namespace: "argocd",
    data: { "policy.csv": "p, role:dev, applications, get, */*, allow\n" },
  },
  projects: [
    { name: "default" },
    {
      name: "payments",
      roles: [
        {
          name: "deployer",
          groups: ["payments-team"],
          policies: [
            "p, proj:payments:deployer, applications, sync, payments/*, allow",
          ],
        },
      ],
    },
  ],
  ...overrides,
});
