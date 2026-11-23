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

  it.each([0, 65536, 5432.5])("refuses the port %j", async (port) => {
    await expect(
      validation().get({ target: { ...target, port } })
    ).rejects.toThrow("port");
  });

  it("rejects as not implemented", async () => {
    await expect(validation().get({ target })).rejects.toThrow(
      "pg-vaulted install.validation.get is not implemented"
    );
  });

  it("the result schema accepts grantable roles", () => {
    const validated = { grantableRoles: ["analyst", "reporting"] };

    expect(installValidation.parse(validated)).toEqual(validated);
  });
});
