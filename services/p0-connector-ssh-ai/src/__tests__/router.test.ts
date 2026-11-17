import { describe, expect, it } from "vitest";

import { connectorRouter } from "../router.ts";

describe("connectorRouter", () => {
  it("serves the session access, its own routes and metadata under ssh-ai", () => {
    expect(Object.keys(connectorRouter._def.procedures).sort()).toEqual([
      "ssh-ai.accesses.session.deleteUser",
      "ssh-ai.accesses.session.identifyUser",
      "ssh-ai.accesses.session.list",
      "ssh-ai.accesses.session.provisionUser",
      "ssh-ai.accesses.session.setPoliciesForUser",
      "ssh-ai.install.sessions.end",
      "ssh-ai.install.validation.get",
      "ssh-ai.metadata.get",
    ]);
  });
});
