import { ConnectorError } from "@p0security/connector-core";
import { describe, expect, it } from "vitest";

import {
  CLICKHOUSE_REFUSAL_REASONS,
  clickhouseRefusalReason,
  refusal,
} from "../refusals.ts";

describe("the refusal reasons", () => {
  it("are exactly the contract's closed set", () => {
    expect([...CLICKHOUSE_REFUSAL_REASONS].sort()).toEqual([
      "ambiguous_member",
      "domain_not_allowed",
      "not_member",
      "not_p0_role",
    ]);
  });

  it("parse each reason, and nothing else", () => {
    for (const reason of CLICKHOUSE_REFUSAL_REASONS) {
      expect(clickhouseRefusalReason.safeParse(reason).success).toBe(true);
    }
    expect(clickhouseRefusalReason.safeParse("other").success).toBe(false);
  });
});

describe("refusal", () => {
  it("is a validation_error carrying its reason with the rest of the payload", () => {
    const error = refusal({
      reason: "not_member",
      message: "Join the organization first.",
      payload: { email: "alice@acme.com" },
    });

    expect(error).toBeInstanceOf(ConnectorError);
    expect(error.data).toEqual({
      type: "validation_error",
      message: "Join the organization first.",
      payload: { email: "alice@acme.com", reason: "not_member" },
    });
  });

  it("keeps its own reason over one in the payload", () => {
    const error = refusal({
      reason: "not_p0_role",
      message: "no",
      payload: { reason: "other" },
    });

    expect(error.data.payload.reason).toBe("not_p0_role");
  });
});
