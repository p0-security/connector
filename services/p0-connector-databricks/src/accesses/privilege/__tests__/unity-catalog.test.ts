import { ConnectorError } from "@p0security/connector";
import { describe, expect, it } from "vitest";

import {
  DatabricksNeverGrantablePrivileges,
  DatabricksSecurableTypes,
  databricksGrantKey,
  parseDatabricksGrantKey,
} from "../../../index.ts";
import type { Securable } from "../definition.ts";
import { isUnknownPrincipal } from "../unity-catalog.ts";

describe("grant keys", () => {
  it.each<[string, Securable]>([
    ["USE_CATALOG", { type: "catalog", fullName: "main" }],
    ["USE_SCHEMA", { type: "schema", fullName: "main.sales" }],
    ["SELECT", { type: "table", fullName: "main.sales.orders" }],
    ["READ_VOLUME", { type: "volume", fullName: "main.raw.files" }],
    ["EXECUTE", { type: "function", fullName: "main.util.mask" }],
    // Any privilege name a stored grant may name, not only ones P0 grants.
    ["CREATE_CONNECTION", { type: "catalog", fullName: "Main" }],
  ])("round-trips %s on %o", (privilege, securable) => {
    const key = databricksGrantKey(privilege, securable);

    expect(key).toBe(`${privilege}@${securable.type}:${securable.fullName}`);
    expect(parseDatabricksGrantKey(key)).toEqual({ privilege, securable });
  });

  it.each([
    "SELECT",
    "SELECT@table",
    "SELECT@table:",
    "SELECT@table:main.sales",
    "SELECT@table:main..orders",
    "SELECT@view:main.sales.orders",
    "select@table:main.sales.orders",
    "ALL PRIVILEGES@catalog:main",
    "@catalog:main",
  ])("refuses %j", (key) => {
    expect(parseDatabricksGrantKey(key)).toBeNull();
  });

  it.each(DatabricksNeverGrantablePrivileges)(
    "refuses a key naming the never-grantable %j, as the stored-grant parser does",
    (privilege) => {
      const key = databricksGrantKey(privilege, {
        type: "catalog",
        fullName: "main",
      });

      expect(parseDatabricksGrantKey(key)).toBeNull();
    }
  );

  it("exports every securable type", () => {
    expect(DatabricksSecurableTypes).toEqual([
      "catalog",
      "schema",
      "table",
      "volume",
      "function",
    ]);
  });
});

describe("isUnknownPrincipal", () => {
  /** A failed Databricks call, as `databricksRequest` reports it. */
  const failed = (status: number, errorCode?: string) =>
    new ConnectorError({
      type: status === 404 ? "object_not_found" : "validation_error",
      message: "failed",
      payload: {
        requestId: "req",
        status,
        ...(errorCode !== undefined ? { errorCode } : {}),
      },
    });

  it.each([
    [400, "PRINCIPAL_DOES_NOT_EXIST", true],
    [404, "PRINCIPAL_DOES_NOT_EXIST", true],
    [404, undefined, false],
    [404, "NOT_FOUND", false],
    [404, "RESOURCE_DOES_NOT_EXIST", false],
    [404, "TABLE_DOES_NOT_EXIST", false],
    [403, "PRINCIPAL_DOES_NOT_EXIST", false],
    [500, "PRINCIPAL_DOES_NOT_EXIST", false],
  ])("is %i with %s → %s", (status, errorCode, expected) => {
    expect(isUnknownPrincipal(failed(status, errorCode))).toBe(expected);
  });

  it("is false for an error that isn't a failed Databricks call", () => {
    expect(isUnknownPrincipal(new Error("PRINCIPAL_DOES_NOT_EXIST"))).toBe(
      false
    );
  });
});
