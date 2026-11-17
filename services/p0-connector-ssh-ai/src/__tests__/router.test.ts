import { describe, expect, it } from "vitest";

import { connectorRouter } from "../router.ts";

describe("connectorRouter", () => {
  it("serves install validation and metadata under ssh-ai, and no access yet", () => {
    expect(Object.keys(connectorRouter._def.procedures).sort()).toEqual([
      "ssh-ai.install.validation.get",
      "ssh-ai.metadata.get",
    ]);
  });
});
