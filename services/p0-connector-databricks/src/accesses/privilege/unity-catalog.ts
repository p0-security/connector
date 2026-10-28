import { ConnectorError } from "@p0security/connector-core";
import { z } from "zod";

import { failedRequest, isNotFoundWith, parse } from "../../databricks/api.ts";
import type { DatabricksWorkspaceClient } from "../../databricks/client.ts";
import { unknownDatabricksUser } from "../common/handler.ts";
import {
  PRIVILEGE_NAME,
  SECURABLE_TYPES,
  type Securable,
  requestGrant,
} from "./definition.ts";

/** Guards against a server that keeps returning a next page. */
const MAX_PAGES = 1_000;

/**
 * Error codes the Unity Catalog permissions API returns, on a 404, when the
 * securable itself is gone. Only a 404 carrying one of these counts as
 * "already revoked": a 404 without one (a proxy's page, or a 404 from
 * somewhere other than the permissions API) and the generic `NOT_FOUND` and
 * `RESOURCE_DOES_NOT_EXIST` don't, nor does a missing principal or metastore.
 */
const SECURABLE_NOT_FOUND_CODES = new Set([
  "CATALOG_DOES_NOT_EXIST",
  "SCHEMA_DOES_NOT_EXIST",
  "TABLE_DOES_NOT_EXIST",
  "VOLUME_DOES_NOT_EXIST",
  "FUNCTION_DOES_NOT_EXIST",
]);

/**
 * Error codes the Unity Catalog permissions API returns, on a 400 or 404,
 * for a principal the metastore doesn't know. Accepted but unverified (build
 * ticket 22). The generic `NOT_FOUND` and `RESOURCE_DOES_NOT_EXIST`, and a
 * status without a code, never count: on a revoke, a false match would
 * report access as removed while it stays.
 */
const UNKNOWN_PRINCIPAL_CODES = new Set(["PRINCIPAL_DOES_NOT_EXIST"]);

/**
 * Whether `error` says the principal doesn't exist: a 400 or 404 carrying
 * one of {@link UNKNOWN_PRINCIPAL_CODES}.
 */
export const isUnknownPrincipal = (error: unknown) => {
  const failed = failedRequest(error);
  return (
    (failed?.status === 400 || failed?.status === 404) &&
    failed.errorCode !== undefined &&
    UNKNOWN_PRINCIPAL_CODES.has(failed.errorCode)
  );
};

const catalogOf = ({ fullName }: Securable) => {
  const [catalog = fullName] = fullName.split(".");
  return catalog;
};

/** Identifies a securable. UC names are case-insensitive, so the name is lowercased. */
export const securableKey = ({ type, fullName }: Securable) =>
  `${type}:${fullName.toLowerCase()}`;

/**
 * A direct grant as the `directGrants` lister keys it, e.g.
 * `SELECT@table:main.sales.orders`. P0's control plane stores these keys, so
 * the format must not change; {@link parseGrantKey} reads one back.
 */
export const grantKey = (privilege: string, { type, fullName }: Securable) =>
  `${privilege}@${type}:${fullName}`;

const GRANT_KEY = new RegExp(
  `^(${PRIVILEGE_NAME})@(${SECURABLE_TYPES.join("|")}):(.+)$`
);

/**
 * Reads a key made by {@link grantKey}, or returns `null` for anything else.
 * A key parses exactly when the grant it names would pass the stored-grant
 * parser: any upper-case privilege name, not only one P0 grants, but never
 * one of the never-grantable privileges, and a full name with as many parts
 * as its type has. The `directGrants` lister reports every direct grant a
 * user holds, so a key it returns for `MANAGE`, say, parses to `null`.
 */
export const parseGrantKey = (
  key: string
): { privilege: string; securable: Securable } | null => {
  const [, privilege, securableType, fullName] = GRANT_KEY.exec(key) ?? [];
  const grant = requestGrant.safeParse({ securableType, fullName, privilege });
  if (!grant.success) return null;
  return {
    privilege: grant.data.privilege,
    securable: {
      type: grant.data.securableType,
      fullName: grant.data.fullName,
    },
  };
};

const permissionsPath = ({ type, fullName }: Securable) =>
  `/api/2.1/unity-catalog/permissions/${type}/${encodeURIComponent(fullName)}`;

const permissionsResponse = z.object({
  privilege_assignments: z
    .array(
      z.object({
        principal: z.string(),
        privileges: z.array(z.string()).optional(),
      })
    )
    .optional(),
});

/**
 * Whether `error` says the securable doesn't exist. Revoking from a dropped
 * securable counts as done, so this fails closed: it needs a 404 carrying
 * one of {@link SECURABLE_NOT_FOUND_CODES}, not just a 404.
 */
export const isSecurableNotFound = (error: unknown) =>
  isNotFoundWith(error, SECURABLE_NOT_FOUND_CODES);

const ucItems = z.array(z.object({ name: z.string().min(1) })).optional();

/** A page of any Unity Catalog list API. The objects sit under the kind's own key. */
const ucPage = z.object({
  catalogs: ucItems,
  schemas: ucItems,
  tables: ucItems,
  volumes: ucItems,
  functions: ucItems,
  next_page_token: z.string().optional(),
});

/** A Unity Catalog list API, named by the key its page lists objects under. */
type UcListKind = Exclude<keyof z.infer<typeof ucPage>, "next_page_token">;

/**
 * Unity Catalog permissions and listing in one workspace, for one request.
 */
export const newUnityCatalog = (workspace: DatabricksWorkspaceClient) => {
  const { requestId } = workspace;

  /**
   * Runs a permissions call on `securable` for `principal`. Databricks
   * refusing the connector there means its principal doesn't hold `MANAGE`
   * on the catalog, either because that grant never landed or because it was
   * taken away. Databricks not knowing `principal` means the requestor has no
   * Databricks user by that email. Either error says what to fix.
   */
  const onSecurable = async <T>(
    securable: Securable,
    principal: string,
    call: () => Promise<T>
  ): Promise<T> => {
    try {
      return await call();
    } catch (error) {
      if (isUnknownPrincipal(error)) {
        throw unknownDatabricksUser({ requestId, principal, cause: error });
      }
      if (failedRequest(error)?.status === 403) {
        const catalog = catalogOf(securable);
        throw new ConnectorError({
          type: "insufficient_privileges",
          message: `P0's service principal can't manage privileges on catalog ${catalog}. Check that it holds MANAGE there, for example by re-applying the catalog's Terraform.`,
          payload: {
            requestId,
            catalog,
            securableType: securable.type,
            fullName: securable.fullName,
          },
          cause: error,
        });
      }
      throw error;
    }
  };

  /**
   * The privileges `principal` holds directly on `securable`. Inherited
   * privileges are not included, because the permissions `GET` returns only
   * direct assignments.
   */
  const directPrivileges = async (
    securable: Securable,
    principal: string
  ): Promise<Set<string>> =>
    await onSecurable(securable, principal, async () => {
      const response = parse({
        schema: permissionsResponse,
        data: await workspace.call({
          method: "GET",
          path: permissionsPath(securable),
          query: { principal },
        }),
        what: "Unity Catalog permissions",
        requestId,
      });
      const assignments = (response.privilege_assignments ?? []).filter(
        (assignment) =>
          assignment.principal.toLowerCase() === principal.toLowerCase()
      );
      return new Set(assignments.flatMap((a) => a.privileges ?? []));
    });

  /** Adds or removes `principal`'s privileges on `securable`. */
  const updatePrivileges = async (
    securable: Securable,
    principal: string,
    change: { add: string[] } | { remove: string[] }
  ) =>
    await onSecurable(securable, principal, async () => {
      await workspace.call({
        method: "PATCH",
        path: permissionsPath(securable),
        body: { changes: [{ principal, ...change }] },
      });
    });

  /**
   * Lists every object a Unity Catalog list API returns, following
   * `next_page_token`. `max_results=0` asks for the server's own page size.
   */
  const list = async (kind: UcListKind, query: Record<string, string> = {}) => {
    const items: { name: string }[] = [];
    let pageToken: string | undefined;
    for (let count = 0; count < MAX_PAGES; count++) {
      const response = parse({
        schema: ucPage,
        data: await workspace.call({
          method: "GET",
          path: `/api/2.1/unity-catalog/${kind}`,
          query: {
            ...query,
            max_results: "0",
            ...(pageToken ? { page_token: pageToken } : {}),
          },
        }),
        what: `Unity Catalog ${kind} list`,
        requestId,
      });
      items.push(...(response[kind] ?? []));
      pageToken = response.next_page_token || undefined;
      if (!pageToken) return items;
    }
    throw new ConnectorError({
      type: "unknown",
      message: `Databricks Unity Catalog ${kind} list returned more than ${MAX_PAGES} pages`,
      payload: { requestId, kind },
    });
  };

  return { directPrivileges, updatePrivileges, list };
};

export type UnityCatalog = ReturnType<typeof newUnityCatalog>;
