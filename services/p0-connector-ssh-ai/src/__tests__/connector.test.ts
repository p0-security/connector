import { describe, expect, it } from "vitest";

import * as contract from "../connector.ts";

describe("the contract the control plane reads", () => {
  it("has the spec of the session access", () => {
    expect(Object.keys(contract.SshAiConnectorSpec)).toEqual(["session"]);
    expect(contract.SshAiConnectorSpec.session.kind).toBe("resource-root");
  });

  it("has the closed sets P0 reads off a failed call", () => {
    expect(contract.SSH_AI_RUN_SCRIPT_FAILURES).toEqual([
      "timeout",
      "command_failed",
      "instance_unreachable",
    ]);
    expect(contract.SSH_AI_SECRET_STEPS).toEqual([
      "describe_secret",
      "create_secret",
      "write_secret",
      "delete_secret",
    ]);
    expect(contract.SSH_AI_INSTALL_STEPS).toEqual(["managed_instances"]);
  });

  it("has the schemas of what P0 sends", () => {
    expect(
      contract.requestContext.safeParse({
        requestId: "r1",
        secrets: { manager: "aws", region: "us-west-2" },
        instance: { id: "i-0123456789abcdef0", region: "us-west-2" },
      }).success
    ).toBe(true);
    expect(
      contract.installContext.safeParse({ region: "us-west-2" }).success
    ).toBe(true);
  });

  it("does not hold the Lambda handler", () => {
    expect(contract).not.toHaveProperty("handler");
  });
});
