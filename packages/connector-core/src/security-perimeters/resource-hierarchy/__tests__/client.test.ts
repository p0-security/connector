import { describe, expect, it, vi } from "vitest";
import { z } from "zod";

import { newResourceHierarchyConnectorMethods } from "../client.ts";
import { newZodResourceHierarchyParsers } from "../parsers.ts";

const parsers = newZodResourceHierarchyParsers({
  userBody: z.string(),
  userId: z.string(),
  resourceBody: z.string(),
  policy: z.string(),
  resourceId: z.string(),
  listerQuery: z.object({ type: z.string() }),
  listerResponse: z.array(z.object({ key: z.string(), value: z.string() })),
  requestContext: z.object({ requestId: z.string() }),
});

const procedure = () => ({ mutate: vi.fn(), query: vi.fn() });

const newScopedClient = () => ({
  identifyUser: procedure(),
  provisionUser: procedure(),
  deleteUser: procedure(),
  createAccessResource: procedure(),
  deleteAccessResource: procedure(),
  addPoliciesToResource: procedure(),
  removePoliciesFromResource: procedure(),
  bindAccessResource: procedure(),
  unbindAccessResource: procedure(),
  list: procedure(),
});

const params = {
  userId: "p0_user",
  userBody: "p0_user",
  context: { requestId: "test-request-id" },
};

describe("resource hierarchy client deleteUser", () => {
  it("sends the request to the deleteUser procedure and returns null", async () => {
    const scopedClient = newScopedClient();
    scopedClient.deleteUser.mutate.mockResolvedValue(null);
    const methods = newResourceHierarchyConnectorMethods(
      parsers,
      // The test stub only implements the calls the client makes.
      scopedClient as unknown as Parameters<
        typeof newResourceHierarchyConnectorMethods
      >[1]
    );

    await expect(methods.deleteUser(params)).resolves.toBeNull();
    expect(scopedClient.deleteUser.mutate).toHaveBeenCalledWith(params);
  });

  it("passes the connector's error through", async () => {
    const scopedClient = newScopedClient();
    scopedClient.deleteUser.mutate.mockRejectedValue(
      new Error("Invalid Postgres role: the connector's own identity")
    );
    const methods = newResourceHierarchyConnectorMethods(
      parsers,
      scopedClient as unknown as Parameters<
        typeof newResourceHierarchyConnectorMethods
      >[1]
    );

    await expect(methods.deleteUser(params)).rejects.toThrow(
      "the connector's own identity"
    );
  });
});
