import { ConnectorError } from "@p0security/connector";
import { describe, expect, it } from "vitest";

import { mapMemberVerificationError } from "../../../util.ts";

// Faithful stand-ins for the sp-shared errors that `verifyMember` throws: plain
// Error subclasses carrying a `type` discriminant (ValidationError -> "validate"
// for a policy denial, ProxyError -> "proxy" for an upstream lookup failure).
const validationError = (message: string) =>
  Object.assign(new Error(message), { type: "validate" });
const proxyError = (message: string) =>
  Object.assign(new Error(message), { type: "proxy" });

describe("mapMemberVerificationError", () => {
  it("maps a policy denial (ValidationError) to a PRECONDITION_FAILED error", () => {
    const cause = validationError(
      "Domain verification failed for member user:x@evil.com."
    );

    const result = mapMemberVerificationError(cause);

    expect(result).toBeInstanceOf(ConnectorError);
    expect(result.data.type).toBe("validation_error");
    expect(result.code).toBe("PRECONDITION_FAILED");
    // The actionable reason is preserved, not buried in a generic 500.
    expect(result.message).toContain("Domain verification failed");
    expect(result.cause).toBe(cause);
  });

  it("maps an upstream lookup failure (ProxyError) to upstream_unavailable", () => {
    const cause = proxyError("Error validating service account 'sa@p.iam'.");

    const result = mapMemberVerificationError(cause);

    expect(result).toBeInstanceOf(ConnectorError);
    expect(result.data.type).toBe("upstream_unavailable");
    expect(result.code).toBe("SERVICE_UNAVAILABLE");
  });

  it("maps an unrecognized error to unknown", () => {
    const result = mapMemberVerificationError(new Error("boom"));

    expect(result).toBeInstanceOf(ConnectorError);
    expect(result.data.type).toBe("unknown");
  });
});
