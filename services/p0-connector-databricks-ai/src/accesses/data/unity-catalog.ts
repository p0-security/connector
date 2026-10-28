import { ConnectorError } from "@p0security/connector";
import { z } from "zod";

import { failedRequest, isNotFoundWith, parse } from "../../databricks/api.ts";
import type { DatabricksWorkspaceClient } from "../../databricks/client.ts";
import type { SecurableType } from "./definition.ts";

/** Guards against a server that keeps returning a next page. */
// Higher than the agent principal's 100, since a schema's tables can run
// to many server-sized pages, and no real list comes near it.
const MAX_PAGES = 1_000;

/** A data securable, as the permissions API takes it. */
export type PermissionsSecurable = {
  type: SecurableType;
  fullName: string;
};

/**
 * Error codes the Unity Catalog APIs return, on a 404, when the securable
 * itself is gone. Only a 404 carrying one of these counts as gone: a 404
 * without one (a proxy's page) and the generic `NOT_FOUND` and
 * `RESOURCE_DOES_NOT_EXIST` don't, nor does a missing principal.
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
 * for a principal the metastore doesn't know. Accepted but unverified. The
 * generic `NOT_FOUND` and `RESOURCE_DOES_NOT_EXIST`, and a status without a
 * code, never count: on a revoke, a false match would report access as
 * removed while it stays.
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

/**
 * Whether `error` says the securable doesn't exist. Revoking from, or
 * transferring out of, a dropped securable counts as done, so this fails
 * closed: it needs a 404 carrying one of {@link SECURABLE_NOT_FOUND_CODES}.
 */
export const isSecurableNotFound = (error: unknown) =>
  isNotFoundWith(error, SECURABLE_NOT_FOUND_CODES);

/** Identifies a securable. UC names are case-insensitive, so the name is lowercased. */
export const securableKey = ({ type, fullName }: PermissionsSecurable) =>
  `${type}:${fullName.toLowerCase()}`;

const catalogOf = ({ fullName }: PermissionsSecurable) => {
  const [catalog = fullName] = fullName.split(".");
  return catalog;
};

const permissionsPath = ({ type, fullName }: PermissionsSecurable) =>
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

const ucItem = z.object({
  name: z.string().min(1),
  full_name: z.string().optional(),
  owner: z.string().optional(),
});

/** One object a Unity Catalog list or get API returns. */
export type UcItem = z.infer<typeof ucItem>;

const ucItems = z.array(ucItem).optional();

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
export type UcListKind = Exclude<
  keyof z.infer<typeof ucPage>,
  "next_page_token"
>;

/** The Unity Catalog objects an agent can own, by the API that serves them. */
export type OwnableKind = "functions" | "tables" | "volumes";

/**
 * Unity Catalog permissions, ownership and listing in one workspace, for one
 * request.
 */
export const newUnityCatalog = (workspace: DatabricksWorkspaceClient) => {
  const { requestId } = workspace;

  /**
   * Runs a permissions call on `securable`. Databricks refusing the
   * connector there means its principal isn't the metastore admin, so the
   * error says to fix that. A principal the metastore doesn't know is left
   * as Databricks' own failure, so a grant to a principal that has only just
   * been created stays retryable.
   */
  const onSecurable = async <T>(
    securable: PermissionsSecurable,
    call: () => Promise<T>
  ): Promise<T> => {
    try {
      return await call();
    } catch (error) {
      if (failedRequest(error)?.status === 403) {
        const catalog = catalogOf(securable);
        throw new ConnectorError({
          type: "insufficient_privileges",
          message: `P0's service principal can't manage privileges on ${securable.type} ${securable.fullName}. Check that it is a metastore admin, for example by re-applying the account's Terraform.`,
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
    securable: PermissionsSecurable,
    principal: string
  ): Promise<Set<string>> =>
    await onSecurable(securable, async () => {
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
    securable: PermissionsSecurable,
    principal: string,
    change: { add: string[] } | { remove: string[] }
  ) =>
    await onSecurable(securable, async () => {
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
  const list = async (
    kind: UcListKind,
    query: Record<string, string> = {}
  ): Promise<UcItem[]> => {
    const items: UcItem[] = [];
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

  /** One table or volume, with its owner. */
  const get = async (kind: "tables" | "volumes", fullName: string) =>
    parse({
      schema: ucItem,
      data: await workspace.call({
        method: "GET",
        path: `/api/2.1/unity-catalog/${kind}/${encodeURIComponent(fullName)}`,
      }),
      what: `Unity Catalog ${kind}`,
      requestId,
    });

  /**
   * Makes `owner` the owner of one table, volume or function. A metastore
   * admin may change any object's owner.
   *
   * The INT-810 live check saw this `PATCH` move `owner` on a table the
   * agent created.
   *
   * TODO(INT-810): that it does the same for volumes and functions. If it
   * doesn't, the fallback is SQL `ALTER ... OWNER TO` on the warehouse.
   */
  const setOwner = async (kind: OwnableKind, fullName: string, owner: string) =>
    await workspace.call({
      method: "PATCH",
      path: `/api/2.1/unity-catalog/${kind}/${encodeURIComponent(fullName)}`,
      body: { owner },
    });

  return { directPrivileges, updatePrivileges, list, get, setOwner };
};

export type UnityCatalog = ReturnType<typeof newUnityCatalog>;
