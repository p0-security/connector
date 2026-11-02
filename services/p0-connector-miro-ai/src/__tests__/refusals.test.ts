import { ConnectorError } from "@p0security/connector-core";
import { describe, expect, it } from "vitest";

import { refusal } from "../refusals.ts";

describe("refusal", () => {
  it("is a validation_error carrying its reason beside the payload", () => {
    const error = refusal({
      reason: "not_in_team",
      message: "Your Miro user isn't in team Dev team.",
      payload: { team: "dev" },
    });

    expect(error).toBeInstanceOf(ConnectorError);
    expect(error.data).toEqual({
      type: "validation_error",
      message: "Your Miro user isn't in team Dev team.",
      payload: { team: "dev", reason: "not_in_team" },
    });
  });

  // The reason is the one the type checked, whatever the payload holds.
  it("keeps its reason over one in the payload", () => {
    const error = refusal({
      reason: "pending_invite",
      message: "You have a pending invite.",
      payload: { reason: "something_else" },
    });

    expect(error.data.payload.reason).toBe("pending_invite");
  });
});
