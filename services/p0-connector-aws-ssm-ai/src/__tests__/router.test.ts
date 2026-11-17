import { describe, expect, it } from "vitest";

import { connectorRouter } from "../router.ts";

describe("connectorRouter", () => {
  it("serves install validation and metadata under aws-ssm-ai, and no access yet", () => {
    expect(Object.keys(connectorRouter._def.procedures).sort()).toEqual([
      "aws-ssm-ai.install.validation.get",
      "aws-ssm-ai.metadata.get",
    ]);
  });
});
