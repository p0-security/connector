import { afterEach, describe, expect, it, vi } from "vitest";

import {
  ARGOCD_ORIGIN,
  installedState,
  newFakeArgoCd,
} from "../argocd/__tests__/fake-argocd.ts";
import { argoCdClientFor } from "../argocd/client.ts";
import {
  FORBIDDEN_PERMISSIONS,
  assertLeastPrivilege,
  heldForbiddenPermissions,
} from "../self-check.ts";
import { ARGOCD_HOST, TOKEN, connectorError, logger } from "./fixtures.ts";

const client = () =>
  argoCdClientFor({ url: ARGOCD_ORIGIN, token: TOKEN, logger });

/** The fake's form of a permission: `<resource>/<action>/<object>`. */
const fakeForm = ({
  resource,
  action,
  object,
}: (typeof FORBIDDEN_PERMISSIONS)[number]) => `${resource}/${action}/${object}`;

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("FORBIDDEN_PERMISSIONS", () => {
  // The spec's list (§4), in its order.
  it("is the spec's five permissions", () => {
    expect(FORBIDDEN_PERMISSIONS).toEqual([
      { resource: "applications", action: "sync", object: "*/*" },
      { resource: "applications", action: "delete", object: "*/*" },
      { resource: "projects", action: "update", object: "*" },
      { resource: "accounts", action: "update", object: "*" },
      { resource: "clusters", action: "update", object: "*" },
    ]);
  });
});

describe("heldForbiddenPermissions", () => {
  it("asks can-i about each permission, its object's slash a slash", async () => {
    const argocd = newFakeArgoCd(installedState());

    await expect(heldForbiddenPermissions(client())).resolves.toEqual([]);
    expect(argocd.calls().sort()).toEqual(
      [
        "applications/sync/*/*",
        "applications/delete/*/*",
        "projects/update/*",
        "accounts/update/*",
        "clusters/update/*",
      ]
        .map((path) => `GET ${ARGOCD_ORIGIN}/api/v1/account/can-i/${path}`)
        .sort()
    );
  });

  it.each(FORBIDDEN_PERMISSIONS)(
    "finds $resource, $action, $object when the account holds it",
    async (permission) => {
      const state = installedState();
      state.permissions.add(fakeForm(permission));
      newFakeArgoCd(state);

      await expect(heldForbiddenPermissions(client())).resolves.toEqual([
        permission,
      ]);
    }
  );

  // What the install steps give the account is never on the list.
  it("doesn't count the account's own permissions", async () => {
    const state = installedState();
    state.permissions.add("applications/get/*");
    state.permissions.add("applications/update/platform/argocd");
    newFakeArgoCd(state);

    await expect(heldForbiddenPermissions(client())).resolves.toEqual([]);
  });
});

describe("assertLeastPrivilege", () => {
  it("passes an account that holds none of them", async () => {
    newFakeArgoCd(installedState());

    await expect(
      assertLeastPrivilege(client(), ARGOCD_HOST)
    ).resolves.toBeUndefined();
  });

  it("refuses with self_check_failed, naming every permission held, in order", async () => {
    const state = installedState();
    state.permissions.add("clusters/update/*");
    state.permissions.add("applications/sync/*/*");
    newFakeArgoCd(state);

    const { data } = await connectorError(() =>
      assertLeastPrivilege(client(), ARGOCD_HOST)
    );

    expect(data).toEqual({
      type: "validation_error",
      message: `The p0-connector account on Argo CD at ${ARGOCD_HOST} may do more than the connector needs ("applications, sync, */*", "clusters, update, *"), so the connector grants nothing. Remove those permissions from the account's role in argocd-rbac-cm.`,
      payload: {
        host: ARGOCD_HOST,
        held: "applications, sync, */*; clusters, update, *",
        reason: "self_check_failed",
      },
    });
  });

  it.each(FORBIDDEN_PERMISSIONS)(
    "refuses an account that holds $resource, $action, $object alone",
    async (permission) => {
      const state = installedState();
      state.permissions.add(fakeForm(permission));
      newFakeArgoCd(state);

      const { data } = await connectorError(() =>
        assertLeastPrivilege(client(), ARGOCD_HOST)
      );

      expect(data.payload).toMatchObject({
        reason: "self_check_failed",
        held: `${permission.resource}, ${permission.action}, ${permission.object}`,
      });
    }
  );
});
