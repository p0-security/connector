// copy of services/p0-connector-harbor/src/harbor/client.ts's shape: the
// calls as a table, a client over the API, and a connect that reads the
// token on every call
import type { Logger } from "@p0security/connector";
import { z } from "zod";

import type { Instance } from "../instance.ts";
import { readApiToken } from "../secrets.ts";
import {
  type ArgoCdApi,
  type ArgoCdCall,
  ArgoCdError,
  isStatus,
  newArgoCdApi,
  pathParts,
  segment,
} from "./api.ts";

/** The ConfigMap Argo CD reads its RBAC policy from. */
export const RBAC_CONFIG_MAP = "argocd-rbac-cm";

/** The one `argocd-rbac-cm` key the connector writes. */
export const P0_POLICY_KEY = "policy.p0.csv";

/** The calls the client makes. */
export const ARGOCD_CALLS = {
  version: { method: "GET", route: "/api/version" },
  userInfo: { method: "GET", route: "/api/v1/session/userinfo" },
  canI: {
    method: "GET",
    route: "/api/v1/account/can-i/{resource}/{action}/{subresource}",
  },
  getApplication: {
    method: "GET",
    route: "/api/v1/applications/{name}",
    permission: "applications, get",
  },
  getResource: {
    method: "GET",
    route: "/api/v1/applications/{name}/resource",
    permission: "applications, get",
  },
  patchResource: {
    method: "POST",
    route: "/api/v1/applications/{name}/resource",
    // The namespace is the instance's: patchRbacConfigMap fills it in.
    permission: `applications, update//ConfigMap/<namespace>/${RBAC_CONFIG_MAP}`,
  },
  listProjects: {
    method: "GET",
    route: "/api/v1/projects",
    permission: "projects, get",
  },
} as const satisfies Record<string, ArgoCdCall>;

// A name Argo CD or Kubernetes gives something: an object name is at most
// 253 characters, so a longer one isn't theirs.
const name = z.string().min(1).max(253);

// A free-form string Argo CD keeps, such as an SSO group.
const text = z.string().max(1024);

/** A list Argo CD's gateway may send as `null` when it is empty. */
const list = <T extends z.ZodType>(item: T) =>
  z
    .array(item)
    .nullish()
    .transform((items) => items ?? []);

/** `GET /api/version`. Anyone may ask; an anonymous caller gets `Version` alone. */
export const versionAnswer = z.object({ Version: z.string().min(1).max(255) });

/**
 * `GET /api/v1/session/userinfo`. The session service answers anyone, so a
 * token Argo CD didn't accept is `loggedIn: false`, not a 401. The gateway
 * writes JSON with Go's encoding/json, which leaves out a field tagged
 * `omitempty` when it is false or empty, so that answer is `{}`.
 */
export const userInfoAnswer = z.union([
  z.object({
    loggedIn: z.literal(true),
    username: name,
    iss: text.default(""),
  }),
  z.object({ loggedIn: z.literal(false).optional() }),
]);

/** `GET /api/v1/account/can-i/...`. */
export const canIAnswer = z.object({ value: z.enum(["yes", "no"]) });

/** A resource an Application manages, as its `status.resources` lists it. */
const managedResource = z.object({
  // The core group is "", which the gateway leaves out.
  group: z.string().max(253).optional().default(""),
  version: z.string().max(63).optional().default(""),
  kind: name,
  // A cluster-scoped resource has none.
  namespace: z.string().max(63).optional().default(""),
  name,
});

export type ManagedResource = z.infer<typeof managedResource>;

/** `GET /api/v1/applications/{name}`, of which the client keeps two things. */
export const applicationAnswer = z.object({
  spec: z.object({ project: name }),
  status: z
    .object({ resources: list(managedResource) })
    .optional()
    .transform((status) => status?.resources ?? []),
});

/** `GET .../resource`: the live object, as a JSON string. */
export const resourceAnswer = z.object({ manifest: z.string() });

/** What the client reads of `argocd-rbac-cm`'s manifest. */
export const rbacManifest = z.object({
  apiVersion: z.literal("v1"),
  kind: z.literal("ConfigMap"),
  metadata: z.object({ name: z.literal(RBAC_CONFIG_MAP), namespace: name }),
  // A ConfigMap with no keys has no `data`.
  data: z
    .record(z.string(), z.string())
    .nullish()
    .transform((data) => data ?? {}),
});

const projectRole = z.object({ name, groups: list(text) });

/** `GET /api/v1/projects`. */
export const projectsAnswer = z.object({
  items: list(
    z.object({
      metadata: z.object({ name }),
      spec: z.object({ roles: list(projectRole) }),
    })
  ),
});

/** An AppProject, and the roles defined on it. */
export type ArgoCdProject = {
  name: string;
  roles: { name: string; groups: string[] }[];
};

/**
 * Where `argocd-rbac-cm` is reached: the Application that manages it, and
 * the namespace it is in.
 */
export type RbacTarget = { app: string; namespace: string };

/** The managing Application's project and name, from `<project>/<app>`. */
export const managingAppOf = ({
  managingApp,
}: Pick<Instance, "managingApp">): { project: string; app: string } => {
  // The instance schema made it `<project>/<app>`.
  const [project = "", app = ""] = managingApp.split("/");
  return { project, app };
};

/** The {@link RbacTarget} an instance names. */
export const rbacTargetOf = (instance: Instance): RbacTarget => ({
  app: managingAppOf(instance).app,
  namespace: instance.namespace,
});

/**
 * What a patch of `argocd-rbac-cm` sets. Only {@link P0_POLICY_KEY}: the
 * connector never writes another key, so it can't change its own
 * privileges.
 */
export type RbacPatch = { [P0_POLICY_KEY]?: string };

/** The query that names `argocd-rbac-cm` on an Application's resource routes. */
const rbacResourceQuery = (namespace: string) => ({
  namespace,
  resourceName: RBAC_CONFIG_MAP,
  version: "v1",
  kind: "ConfigMap",
  // The core group, which Argo CD wants named, if empty.
  group: "",
});

/**
 * The Argo CD calls the connector makes, as the `p0-connector` account on
 * one instance. Every method fails with an {@link ArgoCdError} for anything
 * Argo CD answers, or doesn't; `callArgoCd` turns that into the error P0
 * shows.
 *
 * When anonymous access is on (`users.anonymous.enabled`), Argo CD answers a
 * token it doesn't accept as an anonymous caller, not with a 401: `canI` and
 * `listProjects` then answer for the anonymous user. Call `userInfo` first,
 * which fails with `anonymous`, before relying on either.
 */
export const newArgoCdClient = (api: ArgoCdApi) => {
  /**
   * Runs a call on `argocd-rbac-cm` through the managing Application. Argo
   * CD answers 400 (gRPC's InvalidArgument) when the Application doesn't
   * manage that resource, which fails with `not_managed`. It checks RBAC
   * first, so a 403 comes before it. The query is the client's own and
   * always well formed, so no other 400 is expected here.
   */
  const onRbacConfigMap = async <T>(
    call: ArgoCdCall,
    { app, namespace }: RbacTarget,
    run: () => Promise<T>
  ): Promise<T> => {
    try {
      return await run();
    } catch (error) {
      if (isStatus(error, 400)) {
        throw new ArgoCdError(call, { kind: "not_managed", app, namespace });
      }
      throw error;
    }
  };

  return {
    /** The `Version` Argo CD reports, such as `v3.5.5+2f9b0d1`, unparsed. */
    version: async (): Promise<string> => {
      const { Version } = await api.read({
        call: ARGOCD_CALLS.version,
        path: "/api/version",
        answer: versionAnswer,
      });
      return Version;
    },

    /**
     * Who Argo CD takes the token for: the account's name and the issuer,
     * `argocd` for a local account. Fails with `anonymous` when Argo CD
     * didn't accept the token.
     */
    userInfo: async (): Promise<{ username: string; issuer: string }> => {
      const call = ARGOCD_CALLS.userInfo;
      const info = await api.read({
        call,
        path: "/api/v1/session/userinfo",
        answer: userInfoAnswer,
      });
      if (info.loggedIn !== true) {
        throw new ArgoCdError(call, { kind: "anonymous" });
      }
      return { username: info.username, issuer: info.iss };
    },

    /**
     * Whether the account itself may do `action` on `resource`'s `object`,
     * as `argocd account can-i` asks: `canI("applications", "sync", "*\/*")`.
     * The object's slashes go as slashes.
     */
    canI: async (
      resource: string,
      action: string,
      object: string
    ): Promise<boolean> => {
      const { value } = await api.read({
        call: ARGOCD_CALLS.canI,
        path: `/api/v1/account/can-i/${segment(resource)}/${segment(action)}/${pathParts(object)}`,
        answer: canIAnswer,
      });
      return value === "yes";
    },

    /**
     * The Application's project and the resources it manages. Argo CD
     * answers 403 for an Application that doesn't exist, as it does for one
     * the account may not read.
     */
    getApplication: async (
      app: string
    ): Promise<{ project: string; resources: ManagedResource[] }> => {
      const { spec, status } = await api.read({
        call: ARGOCD_CALLS.getApplication,
        path: `/api/v1/applications/${segment(app)}`,
        answer: applicationAnswer,
      });
      return { project: spec.project, resources: status };
    },

    /**
     * `argocd-rbac-cm`'s keys, read live through the managing Application.
     * Fails with `not_managed` when the Application doesn't manage it, and
     * with `wrong_shape` when what Argo CD returns isn't that ConfigMap.
     */
    readRbacConfigMap: async (
      target: RbacTarget
    ): Promise<{ data: Record<string, string> }> => {
      const call = ARGOCD_CALLS.getResource;
      const { manifest } = await onRbacConfigMap(call, target, () =>
        api.read({
          call,
          path: `/api/v1/applications/${segment(target.app)}/resource`,
          query: rbacResourceQuery(target.namespace),
          answer: resourceAnswer,
        })
      );
      let object: unknown;
      try {
        object = JSON.parse(manifest);
      } catch {
        throw api.unexpected(call, "not_json");
      }
      const parsed = rbacManifest.safeParse(object);
      if (
        !parsed.success ||
        parsed.data.metadata.namespace !== target.namespace
      ) {
        throw api.unexpected(call, "wrong_shape");
      }
      return { data: parsed.data.data };
    },

    /**
     * Merge-patches `argocd-rbac-cm`'s `data` through the managing
     * Application, with argocd-server's own credentials. `{}` changes
     * nothing, which proves the account may patch. Any key but
     * {@link P0_POLICY_KEY} is refused before a call is made: that is a bug.
     *
     * Argo CD takes the patch as a JSON string in the body, so the patch is
     * written to a string here and the API sends that string as JSON.
     */
    patchRbacConfigMap: async (
      target: RbacTarget,
      patch: RbacPatch
    ): Promise<void> => {
      const keys = Object.keys(patch);
      if (keys.some((key) => key !== P0_POLICY_KEY)) {
        throw new Error(
          `the connector writes ${P0_POLICY_KEY} only, not ${keys.join(", ")}`
        );
      }
      const call = {
        ...ARGOCD_CALLS.patchResource,
        permission: `applications, update//ConfigMap/${target.namespace}/${RBAC_CONFIG_MAP}`,
      };
      await onRbacConfigMap(call, target, () =>
        api.send({
          call,
          path: `/api/v1/applications/${segment(target.app)}/resource`,
          query: {
            ...rbacResourceQuery(target.namespace),
            patchType: "application/merge-patch+json",
          },
          body: JSON.stringify({ data: patch }),
        })
      );
    },

    /**
     * The AppProjects the account may see, with each one's roles and the
     * SSO groups each role is bound to.
     */
    listProjects: async (): Promise<ArgoCdProject[]> => {
      const { items } = await api.read({
        call: ARGOCD_CALLS.listProjects,
        path: "/api/v1/projects",
        answer: projectsAnswer,
      });
      return items.map(({ metadata, spec }) => ({
        name: metadata.name,
        roles: spec.roles.map((role) => ({
          name: role.name,
          groups: role.groups,
        })),
      }));
    },
  };
};

export type ArgoCdClient = ReturnType<typeof newArgoCdClient>;

/** An {@link ArgoCdClient} for the instance at `url`, with `token`. */
export const argoCdClientFor = ({
  url,
  token,
  logger,
}: {
  url: string;
  token: string;
  logger: Logger;
}): ArgoCdClient =>
  // `url` is the instance's origin: the instance schema made it so.
  newArgoCdClient(newArgoCdApi({ origin: url, token, logger }));

/** Connects to an instance's Argo CD, as {@link connectArgoCd} does. */
export type ConnectArgoCd = (
  instance: Instance,
  logger: Logger
) => Promise<ArgoCdClient>;

/**
 * An {@link ArgoCdClient} for the instance, as its `p0-connector` account.
 * The token is read from the customer's secret manager now, on every
 * connect, so a rotated token takes effect on the next call. Fails with the
 * secret read's `ConnectorError`.
 */
export const connectArgoCd: ConnectArgoCd = async ({ url, secret }, logger) =>
  argoCdClientFor({ url, token: await readApiToken(secret, logger), logger });
