import { describe, expect, it } from "vitest";

import { connectorRouter } from "../router.ts";

describe("connectorRouter", () => {
  it("serves the session access, its own routes and metadata under aws-ssm-ai", () => {
    expect(Object.keys(connectorRouter._def.procedures).sort()).toEqual([
      "aws-ssm-ai.accesses.session.deleteUser",
      "aws-ssm-ai.accesses.session.identifyUser",
      "aws-ssm-ai.accesses.session.list",
      "aws-ssm-ai.accesses.session.provisionUser",
      "aws-ssm-ai.accesses.session.setPoliciesForUser",
      "aws-ssm-ai.install.sessions.end",
      "aws-ssm-ai.install.validation.get",
      "aws-ssm-ai.metadata.get",
    ]);
  });
});
