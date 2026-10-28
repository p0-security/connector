import type { Logger } from "@p0security/connector-core";

import type { RequestContext } from "../accesses/common/definition.ts";
import { router as consoleRouter } from "../accesses/console/handler.ts";
import { router as sqlRouter } from "../accesses/sql/handler.ts";
import { t } from "../router.ts";
import type { FakeMember, FakePolicy, FakeRole } from "./fake-cloud.ts";
import { CREDENTIALS, EMAIL, ORGANIZATION_ID, SERVICE_ID } from "./fixtures.ts";

/**
 * Drives an access through its real router the way P0's resource hierarchy
 * lifecycle does (`shouldProvisionUser: false`): a grant creates the role,
 * adds the policy and binds the requestor; a revoke runs the downs in
 * reverse, after `identifyUser`.
 */

/** Each access's router, called in-process as P0's tRPC client would call it. */
export const newSqlCaller = (logger: Logger) =>
  sqlRouter(t).createCaller({ logger });
export const newConsoleCaller = (logger: Logger) =>
  consoleRouter(t).createCaller({ logger });

/** The routes a lifecycle calls, for either access. */
export type LifecycleCaller<Policy> = {
  identifyUser: (input: {
    userBody: string;
    context: RequestContext;
  }) => Promise<string | null>;
  createAccessResource: (input: {
    resourceBody: string;
    context: RequestContext;
  }) => Promise<string>;
  addPoliciesToResource: (input: {
    resourceId: string;
    policies: Policy[];
    context: RequestContext;
  }) => Promise<unknown>;
  removePoliciesFromResource: (input: {
    resourceId: string;
    policies: Policy[];
    context: RequestContext;
  }) => Promise<unknown>;
  bindAccessResource: (input: {
    userId: string;
    userBody: string;
    resourceId: string;
    context: RequestContext;
  }) => Promise<unknown>;
  unbindAccessResource: (input: {
    userId: string;
    userBody: string;
    resourceId: string;
    context: RequestContext;
  }) => Promise<unknown>;
  deleteAccessResource: (input: {
    resourceId: string;
    context: RequestContext;
  }) => Promise<unknown>;
};

/** The role P0 names for the request. */
export const ROLE_NAME = "p0_9f3a_alice_brave_otter";

export const REQUEST_ID = "9f3a2b1c-request";

export const DESCRIPTION = `P0 request ${REQUEST_ID} for ${EMAIL}: sql`;

/** The request context P0 sends with every call. */
export const CONTEXT: RequestContext = {
  requestId: REQUEST_ID,
  organization: CREDENTIALS,
  serviceId: SERVICE_ID,
  description: DESCRIPTION,
};

export type Lifecycle<Policy> = {
  policy: Policy;
  context?: RequestContext;
  email?: string;
  roleName?: string;
};

const withDefaults = <Policy>(lifecycle: Lifecycle<Policy>) => ({
  context: CONTEXT,
  email: EMAIL,
  roleName: ROLE_NAME,
  ...lifecycle,
});

/** The grant's three ups, in order. */
export const grant = async <Policy>(
  caller: LifecycleCaller<Policy>,
  lifecycle: Lifecycle<Policy>
): Promise<void> => {
  const { policy, context, email, roleName } = withDefaults(lifecycle);
  await caller.createAccessResource({ resourceBody: roleName, context });
  await caller.addPoliciesToResource({
    resourceId: roleName,
    policies: [policy],
    context,
  });
  await caller.bindAccessResource({
    userId: email,
    userBody: email,
    resourceId: roleName,
    context,
  });
};

/** The revoke's three downs, in the order P0 runs them: the reverse of the grant's. */
export const revoke = async <Policy>(
  caller: LifecycleCaller<Policy>,
  lifecycle: Lifecycle<Policy>
): Promise<void> => {
  const { policy, context, email, roleName } = withDefaults(lifecycle);
  const userId = await caller.identifyUser({ userBody: email, context });
  if (userId === null) throw new Error("identifyUser found no user");
  await caller.unbindAccessResource({
    userId,
    userBody: email,
    resourceId: roleName,
    context,
  });
  await caller.removePoliciesFromResource({
    resourceId: roleName,
    policies: [policy],
    context,
  });
  await caller.deleteAccessResource({ resourceId: roleName, context });
};

/** Grants, runs `during`, then revokes whatever happened, as pg's lifecycle tests do. */
export const withGrant = async <Policy, T>(
  caller: LifecycleCaller<Policy>,
  lifecycle: Lifecycle<Policy>,
  during: () => Promise<T> | T
): Promise<T> => {
  try {
    await grant(caller, lifecycle);
    return await during();
  } finally {
    await revoke(caller, lifecycle);
  }
};

/** The requestor, as a member of the organization. */
export const MEMBER: FakeMember = {
  userId: "f1e2d3c4-member-alice",
  email: EMAIL,
  name: "Alice",
};

/** The policies every P0 role holds, as P0 sends them. */
export const BASE_POLICIES: FakePolicy[] = [
  {
    allowDeny: "ALLOW",
    permissions: ["control-plane:organization:view"],
    resources: [`organization/${ORGANIZATION_ID}`],
  },
  {
    allowDeny: "ALLOW",
    permissions: ["control-plane:service:view"],
    resources: [`instance/${SERVICE_ID}`],
  },
];

/**
 * ClickHouse Cloud's system roles that `console` copies, in a plausible
 * shape: which permissions they really hold is spec assumption 4, for
 * INT-669 to check.
 */
export const systemRoles = (): FakeRole[] => [
  {
    id: "0a1b2c3d-4e5f-4a6b-8c7d-8e9f0a1b2c3d",
    name: "Service Reader",
    type: "system",
    actors: [],
    policies: [
      {
        allowDeny: "ALLOW",
        permissions: [
          "control-plane:organization:view",
          "control-plane:service:view",
          "control-plane:service:view-backups",
        ],
        resources: ["instance/*"],
      },
      {
        allowDeny: "ALLOW",
        permissions: ["sql-console:database:access"],
        resources: ["instance/*"],
        tags: { roleV2: "sql-console-readonly" },
      },
    ],
  },
  {
    id: "1b2c3d4e-5f6a-4b7c-9d8e-9f0a1b2c3d4e",
    name: "Service Admin",
    type: "system",
    actors: [],
    policies: [
      {
        allowDeny: "ALLOW",
        permissions: [
          "control-plane:service:view",
          "control-plane:service:manage",
          "control-plane:service:view",
          "sql-console:database:access",
        ],
        resources: ["instance/*"],
        tags: { roleV2: "sql-console-admin" },
      },
      {
        allowDeny: "DENY",
        permissions: [
          "control-plane:service:delete",
          "control-plane:organization:manage",
        ],
        resources: ["instance/*"],
      },
    ],
  },
];
