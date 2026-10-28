import { createLogger } from "@p0security/connector-core";
import { describe, expect, it, vi } from "vitest";

import { router } from "../accesses/role/handler.ts";
import { newClient } from "../dbclient.ts";
import { t } from "../router.ts";

// No live DB: a call that passes validation stops when it tries to connect.
vi.mock("../dbclient.ts", () => ({
  newClient: vi.fn(async () => {
    throw new Error("db reached");
  }),
}));

const client = router(t).createCaller({ logger: createLogger() });

const context = {
  requestId: "test-request-id",
  db: { host: "localhost", port: 3306, p0User: "root", cloud: "rds" as const },
};

describe.each(["bindAccessResource", "unbindAccessResource"] as const)(
  "%s user namespace check",
  (method) => {
    it("rejects a userBody without the p0 prefix", async () => {
      vi.mocked(newClient).mockClear();
      await expect(
        client[method]({
          userId: "p0_user",
          userBody: "other_user",
          resourceId: "p0_role",
          context,
        })
      ).rejects.toThrow('Username "other_user" is not namespaced');
      expect(newClient).not.toHaveBeenCalled();
    });

    it("lets a p0-prefixed userBody through to the database", async () => {
      await expect(
        client[method]({
          userId: "p0_user",
          userBody: "p0_user",
          resourceId: "p0_role",
          context,
        })
      ).rejects.toThrow("db reached");
    });
  }
);
