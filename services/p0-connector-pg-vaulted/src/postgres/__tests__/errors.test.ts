import { ConnectorError } from "@p0security/connector-core";
import { describe, expect, it } from "vitest";

import { toConnectorError } from "../errors.ts";

const serverError = (code: string) =>
  Object.assign(new Error('permission denied: "SELECT secret"'), {
    code,
    severity: "ERROR",
  });

const codedError = (code: string) =>
  Object.assign(new Error(`connect ${code} 10.0.0.1:5432`), { code });

describe("toConnectorError", () => {
  it.each([
    ["28P01", "insufficient_privileges"],
    ["3D000", "object_not_found"],
    ["08006", "upstream_unavailable"],
    ["57014", "upstream_unavailable"],
    ["XX000", "unknown"],
  ])("maps the SQLSTATE %s to %s", (sqlState, type) => {
    const { data } = toConnectorError(serverError(sqlState));
    expect(data.type).toBe(type);
    expect(data.payload).toEqual({ sqlState });
  });

  it.each([
    ["ECONNREFUSED", "upstream_unavailable", "network path"],
    ["ETIMEDOUT", "upstream_unavailable", "network path"],
    ["ENOTFOUND", "upstream_unavailable", "network path"],
    ["ERR_TLS_CERT_ALTNAME_INVALID", "upstream_unavailable", "certificate"],
    ["SELF_SIGNED_CERT_IN_CHAIN", "upstream_unavailable", "certificate"],
    ["CERT_HAS_EXPIRED", "upstream_unavailable", "certificate"],
    ["FORBIDDEN", "unknown", "does not know"],
  ])("maps the code %s to %s", (code, type, message) => {
    const { data } = toConnectorError(codedError(code));
    expect(data.type).toBe(type);
    expect(data.message).toContain(message);
    expect(data.payload).toEqual({ code });
  });

  it("maps knex's pool timeout to unavailable", () => {
    const timeout = Object.assign(new Error("Knex: Timeout acquiring"), {
      name: "KnexTimeoutError",
    });
    expect(toConnectorError(timeout).data.type).toBe("upstream_unavailable");
  });

  it("maps an error with no code to unknown", () => {
    const { data } = toConnectorError(new TypeError("x is undefined"));
    expect(data.type).toBe("unknown");
    expect(data.payload).toEqual({});
  });

  it("passes a ConnectorError through", () => {
    const error = new ConnectorError({
      type: "validation_error",
      message: "no",
      payload: {},
    });
    expect(toConnectorError(error)).toBe(error);
  });

  it("never quotes the driver's message", () => {
    for (const error of [serverError("42501"), codedError("ECONNRESET")]) {
      expect(JSON.stringify(toConnectorError(error).data)).not.toContain(
        "SELECT secret"
      );
      expect(JSON.stringify(toConnectorError(error).data)).not.toContain(
        "10.0.0.1"
      );
    }
  });
});
