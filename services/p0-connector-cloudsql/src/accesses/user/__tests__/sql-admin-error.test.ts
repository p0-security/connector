import { ConnectorError } from "@p0security/connector-core";
import { GaxiosError } from "gaxios";
import { describe, expect, it } from "vitest";

import { mapSqlAdminError } from "../../../util.ts";

const email = "user@example.com";

// A SQL Admin API failure as googleapis throws it: a GaxiosError whose status
// comes from the HTTP response, or none when the API was never reached.
const sqlAdminError = (message: string, status?: number) => {
  const error = new GaxiosError(message, {} as never);
  error.status = status;
  return error;
};

describe("mapSqlAdminError", () => {
  it.each([
    [400, "validation_error"],
    [401, "insufficient_privileges"],
    [403, "insufficient_privileges"],
    [404, "object_not_found"],
    [409, "already_exists"],
    [429, "rate_limited"],
    [500, "upstream_unavailable"],
    [503, "upstream_unavailable"],
  ] as const)("maps a %i response to %s", (status, type) => {
    const result = mapSqlAdminError(sqlAdminError("failed", status), email);

    expect(result).toBeInstanceOf(ConnectorError);
    expect(result.data.type).toBe(type);
  });

  it("maps a transport failure with no response to upstream_unavailable", () => {
    const result = mapSqlAdminError(sqlAdminError("socket hang up"), email);

    expect(result.data.type).toBe("upstream_unavailable");
    expect(result.data.payload).toEqual({ email });
  });

  it("maps a non-API error to unknown", () => {
    const result = mapSqlAdminError(new Error("boom"), email);

    expect(result.data.type).toBe("unknown");
  });

  it("carries the status and the API's message to the control plane", () => {
    const cause = sqlAdminError("Request had invalid authentication", 401);

    const result = mapSqlAdminError(cause, email);

    expect(result.message).toBe(
      `CloudSQL API request failed for user '${email}' (401): Request had invalid authentication`
    );
    expect(result.data.payload).toEqual({ email, status: 401 });
    expect(result.cause).toBe(cause);
  });

  it("carries the message of a non-API error", () => {
    const result = mapSqlAdminError(new Error("boom"), email);

    expect(result.message).toBe(
      `CloudSQL API request failed for user '${email}': boom`
    );
  });
});
