import { describe, expect, it, vi } from "vitest";

import type { ResourceHierarchyConnectorPrimitives } from "../implementation.ts";
import { buildResourceHierarchySecurityPerimeter } from "../implementation.ts";
import type { ResourceHierarchySchema } from "../schema.ts";

type Schema = ResourceHierarchySchema<string>;

const context = { requestId: "test-request-id" };

const isP0Prefixed = async (name: string) => name.startsWith("p0_");

const newPrimitives = (
  user: "namespaced" | "unchecked"
): ResourceHierarchyConnectorPrimitives<Schema> => ({
  validation: () => ({
    user:
      user === "namespaced"
        ? {
            userIsNamespacedById: isP0Prefixed,
            userIsNamespacedByBody: isP0Prefixed,
          }
        : null,
    resource: null,
  }),
  getUser: vi.fn(),
  createUser: vi.fn(),
  deleteUser: vi.fn(async () => {}),
  createResource: vi.fn(),
  addPolicyToResource: vi.fn(),
  removePolicyFromResource: vi.fn(),
  deleteResource: vi.fn(),
  bindResourceToUser: vi.fn(),
  unbindResourceFromUser: vi.fn(),
  list: vi.fn(),
});

describe("resource hierarchy deleteUser", () => {
  it("deletes a namespaced user through the primitive", async () => {
    const methods = newPrimitives("namespaced");
    const perimeter = buildResourceHierarchySecurityPerimeter(methods);

    await expect(
      perimeter.deleteUser({
        userId: "p0_user",
        userBody: "p0_user",
        context,
      })
    ).resolves.toBeNull();
    expect(methods.deleteUser).toHaveBeenCalledOnce();
    expect(methods.deleteUser).toHaveBeenCalledWith(
      context,
      "p0_user",
      "p0_user"
    );
  });

  it("rejects a userId without the namespace", async () => {
    const methods = newPrimitives("namespaced");
    const perimeter = buildResourceHierarchySecurityPerimeter(methods);

    await expect(
      perimeter.deleteUser({
        userId: "other_user",
        userBody: "p0_user",
        context,
      })
    ).rejects.toThrow("Username other_user is not namespaced");
    expect(methods.deleteUser).not.toHaveBeenCalled();
  });

  it("rejects a userBody without the namespace", async () => {
    const methods = newPrimitives("namespaced");
    const perimeter = buildResourceHierarchySecurityPerimeter(methods);

    await expect(
      perimeter.deleteUser({
        userId: "p0_user",
        userBody: "other_user",
        context,
      })
    ).rejects.toThrow('Username "other_user" is not namespaced');
    expect(methods.deleteUser).not.toHaveBeenCalled();
  });

  it("skips the namespace check when the connector opts out of user validation", async () => {
    const methods = newPrimitives("unchecked");
    const perimeter = buildResourceHierarchySecurityPerimeter(methods);

    await perimeter.deleteUser({
      userId: "alice@example.com",
      userBody: "alice@example.com",
      context,
    });
    expect(methods.deleteUser).toHaveBeenCalledOnce();
  });
});
