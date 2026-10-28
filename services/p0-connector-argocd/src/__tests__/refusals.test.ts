// copy of services/p0-connector-harbor/src/__tests__/refusals.test.ts, with
// Argo CD's reasons
import { ConnectorError } from "@p0security/connector";
import { describe, expect, it } from "vitest";

import { ARGOCD_REFUSAL_REASONS, refusal } from "../refusals.ts";

describe("refusal", () => {
  it("is a validation_error carrying its reason beside the payload", () => {
    const error = refusal({
      reason: "already_held",
      message: "Held.",
      payload: { host: "argocd.example.com" },
    });

    expect(error).toBeInstanceOf(ConnectorError);
    expect(error.data).toEqual({
      type: "validation_error",
      message: "Held.",
      payload: { host: "argocd.example.com", reason: "already_held" },
    });
  });

  // The reason is the one the type checked, whatever the payload holds.
  it("keeps its reason over one in the payload", () => {
    const error = refusal({
      reason: "role_not_found",
      message: "No role.",
      payload: { reason: "something_else" },
    });

    expect(error.data.payload.reason).toBe("role_not_found");
  });
});

// The set is the contract with P0, which words each reason in its own copy:
// a change here is a change P0 has to make too.
it("has exactly the reasons P0 words", () => {
  expect(ARGOCD_REFUSAL_REASONS).toEqual([
    "connector_role",
    "default_role",
    "not_an_email",
    "domain_not_allowed",
    "domain_pattern_unusable",
    "role_not_found",
    "project_not_found",
    "self_check_failed",
    "already_held",
    "policy_not_loaded",
  ]);
});
