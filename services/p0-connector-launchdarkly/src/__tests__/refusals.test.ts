import { ConnectorError } from "@p0security/connector-core";
import { describe, expect, it } from "vitest";

import { refusal } from "../refusals.ts";

describe("refusal", () => {
  it("is a validation_error carrying its reason beside the payload", () => {
    const error = refusal({
      reason: "base_role_ignored",
      message: "Custom roles.",
      payload: { memberId: "m-1" },
    });

    expect(error).toBeInstanceOf(ConnectorError);
    expect(error.data).toEqual({
      type: "validation_error",
      message: "Custom roles.",
      payload: { memberId: "m-1", reason: "base_role_ignored" },
    });
  });

  // The reason is the one the type checked, whatever the payload holds.
  it("keeps its reason over one in the payload", () => {
    const error = refusal({
      reason: "own_member",
      message: "The token's own member.",
      payload: { reason: "something_else" },
    });

    expect(error.data.payload.reason).toBe("own_member");
  });
});
