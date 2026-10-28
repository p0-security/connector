import { ConnectorError } from "@p0security/connector-core";
import { describe, expect, it } from "vitest";

import { mapDriveError, statusOf } from "../errors.ts";

const PAYLOAD = { requestId: "req-1", query: "1XyZ_folder_id" };

/** A Gaxios-shaped failure: status on `code`, reasons in `errors`. */
const driveError = (code: number, reason?: string, message = "refused") =>
  Object.assign(new Error(message), {
    code,
    errors: reason ? [{ domain: "global", reason, message }] : undefined,
  });

describe("statusOf", () => {
  it("reads the status from any of the three places googleapis puts it", () => {
    expect(statusOf({ code: 404 })).toBe(404);
    expect(statusOf({ status: 403 })).toBe(403);
    expect(statusOf({ response: { status: 500 } })).toBe(500);
    expect(statusOf(new Error("socket hang up"))).toBeUndefined();
  });
});

describe("mapDriveError", () => {
  it("maps a 404 to object_not_found", () => {
    expect(mapDriveError(driveError(404), PAYLOAD).data.type).toBe(
      "object_not_found"
    );
  });

  it("maps a plain 403 to insufficient_privileges", () => {
    const { data } = mapDriveError(
      driveError(403, "insufficientFilePermissions"),
      PAYLOAD
    );

    expect(data.type).toBe("insufficient_privileges");
    expect(data.message).toContain("organizer");
  });

  // The per-item ceiling is Drive's to enforce, so this is matched on the shape
  // of the refusal rather than against a hard-coded number.
  it("names residue when the item has hit its permission ceiling", () => {
    const { data } = mapDriveError(
      driveError(
        403,
        "sharingLimitExceeded",
        "The limit of shared users for this item has been reached."
      ),
      PAYLOAD
    );

    expect(data.type).toBe("validation_error");
    expect(data.message).toContain("residue");
    expect(data.message).not.toMatch(/\d/);
  });

  // `sharingRateLimitExceeded` also says "limit", and is a retry rather than a
  // capacity problem.
  it("keeps rate limiting distinct from the ceiling", () => {
    expect(
      mapDriveError(driveError(403, "sharingRateLimitExceeded"), PAYLOAD).data
        .type
    ).toBe("rate_limited");
    expect(mapDriveError(driveError(429), PAYLOAD).data.type).toBe(
      "rate_limited"
    );
  });

  it("maps a 5xx to upstream_unavailable and anything else to unknown", () => {
    expect(mapDriveError(driveError(503), PAYLOAD).data.type).toBe(
      "upstream_unavailable"
    );
    expect(mapDriveError(new Error("socket hang up"), PAYLOAD).data.type).toBe(
      "unknown"
    );
  });

  it("passes an already-categorized error through untouched", () => {
    const original = new ConnectorError({
      type: "dependency_violation",
      message: "already categorized",
      payload: PAYLOAD,
    });

    expect(mapDriveError(original, PAYLOAD)).toBe(original);
  });
});
