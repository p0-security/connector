import { createLogger } from "@p0security/connector-core";
import { describe, expect, it } from "vitest";

import { target } from "../../__tests__/fixtures.ts";
import { t } from "../../router.ts";
import { installValidation } from "../definition.ts";
import { router } from "../handler.ts";

const validation = () => router(t).createCaller({ logger: createLogger() });

describe("install validation", () => {
  it("refuses an input with no target", async () => {
    // @ts-expect-error -- the input is { target }
    await expect(validation().get({})).rejects.toThrow("target");
  });

  it("rejects, not implemented", async () => {
    await expect(validation().get({ target })).rejects.toThrow(
      "pg-vaulted install.validation.get is not implemented"
    );
  });

  it("its result names the roles the manager can hand out", () => {
    const validated = { grantableRoles: ["analyst", "reporting"] };

    expect(installValidation.parse(validated)).toEqual(validated);
  });
});
