import { ConnectorError } from "@p0security/connector";
import { describe, expect, it } from "vitest";

import { refusal } from "../refusals.ts";

describe("refusal", () => {
  it("is a validation_error carrying its reason beside the payload", () => {
    const error = refusal({
      reason: "duplicate_email",
      message: "More than one.",
      payload: { host: "harbor.example.com" },
    });

    expect(error).toBeInstanceOf(ConnectorError);
    expect(error.data).toEqual({
      type: "validation_error",
      message: "More than one.",
      payload: { host: "harbor.example.com", reason: "duplicate_email" },
    });
  });

  // The reason is the one the type checked, whatever the payload holds.
  it("keeps its reason over one in the payload", () => {
    const error = refusal({
      reason: "no_user",
      message: "No one.",
      payload: { reason: "something_else" },
    });

    expect(error.data.payload.reason).toBe("no_user");
  });
});
