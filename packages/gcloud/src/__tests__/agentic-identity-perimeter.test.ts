import type { cloudresourcemanager_v3 } from "@googleapis/cloudresourcemanager";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { newAgenticIdentityPrimitives } from "../agentic-identity/perimeter.ts";

const getOrgId = vi.fn();
const getOrgIdByProjectNumber = vi.fn();

vi.mock("../helpers/ancestry.ts", () => ({
  getOrgId: (...args: unknown[]) => getOrgId(...args),
  getOrgIdByProjectNumber: (...args: unknown[]) =>
    getOrgIdByProjectNumber(...args),
}));

const PERIMETER_PROJECT = "customer";
const PROJECT = "customer-identities";
const ACCOUNT_ID = "p0a-agile-otter-1f2e3d4c";
const EMAIL = `${ACCOUNT_ID}@${PROJECT}.iam.gserviceaccount.com`;
const SUBJECT = "agentic-identity/0123456789abcdef";
const MEMBER =
  "principal://iam.googleapis.com/projects/123456789/locations/global/" +
  `workloadIdentityPools/p0-pool/subject/${SUBJECT}`;

const METADATA = {
  serviceAccountEmail:
    "p0-security-perimeter-sa@customer.iam.gserviceaccount.com",
  projectId: PERIMETER_PROJECT,
};

const CONTEXT = { requestId: "request-id", project: PROJECT };

const USER_BODY = { project: PROJECT, accountId: ACCOUNT_ID, subject: SUBJECT };

const SA_RESOURCE = `projects/${PROJECT}/serviceAccounts/${EMAIL}`;

const OTHER_ROLE_BINDING: cloudresourcemanager_v3.Schema$Binding = {
  role: "roles/iam.serviceAccountTokenCreator",
  members: ["user:someone@example.com"],
};

const gaxiosError = (status: number) =>
  Object.assign(new Error("boom"), {
    code: status,
  });

/** A GCP client stubbed down to the calls this perimeter makes. */
const newFakeClient = (policy: cloudresourcemanager_v3.Schema$Policy = {}) => {
  const serviceAccounts = {
    get: vi.fn().mockResolvedValue({ data: { email: EMAIL } }),
    create: vi.fn().mockResolvedValue({ data: { email: EMAIL } }),
    delete: vi.fn().mockResolvedValue({ data: {} }),
    getIamPolicy: vi.fn().mockResolvedValue({ data: policy }),
    setIamPolicy: vi.fn().mockResolvedValue({ data: policy }),
  };
  return {
    client: { iam: { projects: { serviceAccounts } } } as any,
    serviceAccounts,
  };
};

const primitivesFor = (client: any) =>
  newAgenticIdentityPrimitives(async () => ({
    client,
    metadata: METADATA,
  }));

/** The bindings handed to `setIamPolicy` by the single write a converge makes. */
const writtenBindings = (serviceAccounts: { setIamPolicy: any }) => {
  expect(serviceAccounts.setIamPolicy).toHaveBeenCalledTimes(1);
  const [call] = serviceAccounts.setIamPolicy.mock.calls;
  return call[0].requestBody.policy.bindings;
};

beforeEach(() => {
  vi.clearAllMocks();
  getOrgId.mockResolvedValue("111111111111");
  getOrgIdByProjectNumber.mockResolvedValue("111111111111");
});

describe("agentic identity: namespacing guards", () => {
  const { client } = newFakeClient();
  const { validation } = primitivesFor(client);

  it("accepts the address and body this perimeter mints", async () => {
    const { user } = validation(CONTEXT);
    await expect(user.userIsNamespacedById(EMAIL)).resolves.toBe(true);
    await expect(user.userIsNamespacedByBody(USER_BODY)).resolves.toBe(true);
  });

  it("refuses an address outside the agentic identity namespace", async () => {
    const { user } = validation(CONTEXT);
    await expect(
      user.userIsNamespacedById(`admin@${PROJECT}.iam.gserviceaccount.com`)
    ).resolves.toBe(false);
  });

  it("refuses an address in a different project", async () => {
    const { user } = validation(CONTEXT);
    await expect(
      user.userIsNamespacedById(
        `${ACCOUNT_ID}@someone-else.iam.gserviceaccount.com`
      )
    ).resolves.toBe(false);
  });

  it("refuses a body whose subject is outside P0's namespace", async () => {
    const { user } = validation(CONTEXT);
    await expect(
      user.userIsNamespacedByBody({
        ...USER_BODY,
        subject: "mcps/backend/0123456789abcdef",
      })
    ).resolves.toBe(false);
  });

  it("refuses a body whose account id is outside P0's namespace", async () => {
    const { user } = validation(CONTEXT);
    await expect(
      user.userIsNamespacedByBody({ ...USER_BODY, accountId: "admin" })
    ).resolves.toBe(false);
  });

  it("refuses a body whose project is not a project id", async () => {
    const { user } = validation({ ...CONTEXT, project: "No" });
    await expect(
      user.userIsNamespacedByBody({ ...USER_BODY, project: "No" })
    ).resolves.toBe(false);
  });

  // Delete and converge see only an address, which they check against the
  // context's project; a body naming another project would provision an
  // account those calls then refuse to touch.
  it("refuses a body whose project disagrees with the context", async () => {
    const { user } = validation(CONTEXT);
    await expect(
      user.userIsNamespacedByBody({ ...USER_BODY, project: "customer-other" })
    ).resolves.toBe(false);
  });
});

describe("agentic identity: getUser", () => {
  it("returns the address when the service account exists", async () => {
    const { client, serviceAccounts } = newFakeClient();
    await expect(
      primitivesFor(client).getUser(CONTEXT, USER_BODY)
    ).resolves.toBe(EMAIL);
    expect(serviceAccounts.get).toHaveBeenCalledWith({ name: SA_RESOURCE });
  });

  it("returns null when it does not", async () => {
    const { client, serviceAccounts } = newFakeClient();
    serviceAccounts.get.mockRejectedValue(gaxiosError(404));
    await expect(
      primitivesFor(client).getUser(CONTEXT, USER_BODY)
    ).resolves.toBeNull();
  });

  it("returns null for a deleted account, which GCP answers with a 403", async () => {
    const { client, serviceAccounts } = newFakeClient();
    serviceAccounts.get.mockRejectedValue(gaxiosError(403));
    await expect(
      primitivesFor(client).getUser(CONTEXT, USER_BODY)
    ).resolves.toBeNull();
  });

  it("surfaces any other read failure", async () => {
    const { client, serviceAccounts } = newFakeClient();
    serviceAccounts.get.mockRejectedValue(gaxiosError(500));
    await expect(
      primitivesFor(client).getUser(CONTEXT, USER_BODY)
    ).rejects.toThrow("Error reading agentic identity");
  });
});

describe("agentic identity: createUser", () => {
  it("creates the account the body names, with its description set at creation", async () => {
    const { client, serviceAccounts } = newFakeClient();
    await expect(
      primitivesFor(client).createUser(CONTEXT, USER_BODY)
    ).resolves.toBe(EMAIL);
    expect(serviceAccounts.create).toHaveBeenCalledWith({
      name: `projects/${PROJECT}`,
      requestBody: {
        accountId: ACCOUNT_ID,
        serviceAccount: {
          displayName: "P0 agentic identity",
          description: expect.stringContaining(SUBJECT),
        },
      },
    });
  });

  // Each grant's address is fresh, so an existing account at it belongs to
  // someone else; adopting it would rebind that account to this grant.
  it("refuses to adopt an account that already exists", async () => {
    const { client, serviceAccounts } = newFakeClient();
    serviceAccounts.create.mockRejectedValue(gaxiosError(409));
    await expect(
      primitivesFor(client).createUser(CONTEXT, USER_BODY)
    ).rejects.toThrow(/already exists and was not created for this grant/);
  });

  it("surfaces any other creation failure", async () => {
    const { client, serviceAccounts } = newFakeClient();
    serviceAccounts.create.mockRejectedValue(gaxiosError(403));
    await expect(
      primitivesFor(client).createUser(CONTEXT, USER_BODY)
    ).rejects.toThrow(/Error creating agentic identity/);
  });

  it("refuses a project in another organization", async () => {
    const { client, serviceAccounts } = newFakeClient();
    getOrgId.mockImplementation(async (_client: unknown, project: string) =>
      project === PERIMETER_PROJECT ? "111111111111" : "999999999999"
    );
    await expect(
      primitivesFor(client).createUser(CONTEXT, USER_BODY)
    ).rejects.toThrow(/does not belong to an organization under this account/);
    expect(serviceAccounts.create).not.toHaveBeenCalled();
  });

  it("skips the eligibility lookup when the identity lives in this project", async () => {
    const { client } = newFakeClient();
    await primitivesFor(client).createUser(
      { ...CONTEXT, project: PERIMETER_PROJECT },
      { ...USER_BODY, project: PERIMETER_PROJECT }
    );
    expect(getOrgId).not.toHaveBeenCalled();
  });
});

describe("agentic identity: deleteUser", () => {
  it("deletes the service account", async () => {
    const { client, serviceAccounts } = newFakeClient();
    await primitivesFor(client).deleteUser(CONTEXT, EMAIL);
    expect(serviceAccounts.delete).toHaveBeenCalledWith({ name: SA_RESOURCE });
  });

  it("treats a 404 as success, so teardown is idempotent", async () => {
    const { client, serviceAccounts } = newFakeClient();
    serviceAccounts.delete.mockRejectedValue(gaxiosError(404));
    await expect(
      primitivesFor(client).deleteUser(CONTEXT, EMAIL)
    ).resolves.toBeUndefined();
  });

  it("refuses an address this perimeter did not mint", async () => {
    const { client, serviceAccounts } = newFakeClient();
    await expect(
      primitivesFor(client).deleteUser(
        CONTEXT,
        `admin@${PROJECT}.iam.gserviceaccount.com`
      )
    ).rejects.toThrow(/is not a P0 agentic identity/);
    expect(serviceAccounts.delete).not.toHaveBeenCalled();
  });
});

describe("agentic identity: setPoliciesForUser converges", () => {
  const staleBinding: cloudresourcemanager_v3.Schema$Binding = {
    role: "roles/iam.workloadIdentityUser",
    members: [
      "principal://iam.googleapis.com/projects/123456789/locations/global/" +
        "workloadIdentityPools/p0-pool/subject/agentic-identity/ffffffffffffffff",
    ],
    condition: {
      title: "p0-agentic-identity-expires-2026-01-01T00:00:00Z",
      description: "Impersonation window for a P0 agentic identity.",
      expression: 'request.time < timestamp("2026-01-01T00:00:00Z")',
    },
  };

  const withStalePolicy = () =>
    newFakeClient({
      etag: "etag-1",
      version: 3,
      bindings: [OTHER_ROLE_BINDING, { ...staleBinding }],
    });

  it("replaces a stale binding rather than adding alongside it", async () => {
    const { client, serviceAccounts } = withStalePolicy();
    await primitivesFor(client).setPoliciesForUser(CONTEXT, EMAIL, USER_BODY, [
      { member: MEMBER, expiresAt: "2026-02-02T00:00:00Z" },
    ]);

    expect(writtenBindings(serviceAccounts)).toEqual([
      OTHER_ROLE_BINDING,
      {
        role: "roles/iam.workloadIdentityUser",
        members: [MEMBER],
        condition: {
          title: "p0-agentic-identity-expires-2026-02-02T00:00:00Z",
          description: "Impersonation window for a P0 agentic identity.",
          expression: 'request.time < timestamp("2026-02-02T00:00:00Z")',
        },
      },
    ]);
  });

  it("removes the binding entirely when the policy set is empty", async () => {
    const { client, serviceAccounts } = withStalePolicy();
    await primitivesFor(client).setPoliciesForUser(
      CONTEXT,
      EMAIL,
      USER_BODY,
      []
    );
    expect(writtenBindings(serviceAccounts)).toEqual([OTHER_ROLE_BINDING]);
  });

  it("writes an unconditional binding when the policy carries no expiry", async () => {
    const { client, serviceAccounts } = withStalePolicy();
    await primitivesFor(client).setPoliciesForUser(CONTEXT, EMAIL, USER_BODY, [
      { member: MEMBER },
    ]);
    expect(writtenBindings(serviceAccounts)).toEqual([
      OTHER_ROLE_BINDING,
      { role: "roles/iam.workloadIdentityUser", members: [MEMBER] },
    ]);
  });

  it("converges to the same policy when replayed", async () => {
    const policies = [{ member: MEMBER, expiresAt: "2026-02-02T00:00:00Z" }];
    const first = withStalePolicy();
    await primitivesFor(first.client).setPoliciesForUser(
      CONTEXT,
      EMAIL,
      USER_BODY,
      policies
    );
    const converged = writtenBindings(first.serviceAccounts);

    const second = newFakeClient({ etag: "etag-2", bindings: converged });
    await primitivesFor(second.client).setPoliciesForUser(
      CONTEXT,
      EMAIL,
      USER_BODY,
      policies
    );
    expect(writtenBindings(second.serviceAccounts)).toEqual(converged);
  });

  it("names the member the policy carries, not one of its own choosing", async () => {
    const { client, serviceAccounts } = withStalePolicy();
    const other = MEMBER.replace(SUBJECT, "agentic-identity/aaaaaaaaaaaaaaaa");
    await primitivesFor(client).setPoliciesForUser(CONTEXT, EMAIL, USER_BODY, [
      { member: other },
    ]);
    expect(writtenBindings(serviceAccounts)).toEqual([
      OTHER_ROLE_BINDING,
      { role: "roles/iam.workloadIdentityUser", members: [other] },
    ]);
  });

  it("refuses a member outside P0's subject namespace", async () => {
    const { client, serviceAccounts } = withStalePolicy();
    await expect(
      primitivesFor(client).setPoliciesForUser(CONTEXT, EMAIL, USER_BODY, [
        { member: MEMBER.replace(SUBJECT, "mcps/backend/0123456789abcdef") },
      ])
    ).rejects.toThrow();
    expect(serviceAccounts.setIamPolicy).not.toHaveBeenCalled();
  });

  it("leaves the policy untouched when a member fails verification", async () => {
    const { client, serviceAccounts } = withStalePolicy();
    getOrgIdByProjectNumber.mockResolvedValue("999999999999");
    await expect(
      primitivesFor(client).setPoliciesForUser(CONTEXT, EMAIL, USER_BODY, [
        { member: MEMBER, expiresAt: "2026-02-02T00:00:00Z" },
      ])
    ).rejects.toThrow(/outside this organization/);
    expect(serviceAccounts.setIamPolicy).not.toHaveBeenCalled();
  });

  it("refuses an expiry that is not an ISO 8601 instant", async () => {
    const { client, serviceAccounts } = withStalePolicy();
    await expect(
      primitivesFor(client).setPoliciesForUser(CONTEXT, EMAIL, USER_BODY, [
        {
          member: MEMBER,
          expiresAt: '2026-02-02T00:00:00Z") || request.time < timestamp("',
        },
      ])
    ).rejects.toThrow(/is not an ISO 8601 instant/);
    expect(serviceAccounts.setIamPolicy).not.toHaveBeenCalled();
  });

  it("refuses more than one policy rather than guessing which expiry wins", async () => {
    const { client, serviceAccounts } = withStalePolicy();
    await expect(
      primitivesFor(client).setPoliciesForUser(CONTEXT, EMAIL, USER_BODY, [
        { member: MEMBER, expiresAt: "2026-02-02T00:00:00Z" },
        { member: MEMBER, expiresAt: "2026-03-03T00:00:00Z" },
      ])
    ).rejects.toThrow(/Expected at most one policy/);
    expect(serviceAccounts.setIamPolicy).not.toHaveBeenCalled();
  });

  it("refuses an address this perimeter did not mint", async () => {
    const { client, serviceAccounts } = withStalePolicy();
    await expect(
      primitivesFor(client).setPoliciesForUser(
        CONTEXT,
        `admin@${PROJECT}.iam.gserviceaccount.com`,
        USER_BODY,
        []
      )
    ).rejects.toThrow(/is not a P0 agentic identity/);
    expect(serviceAccounts.getIamPolicy).not.toHaveBeenCalled();
  });
});

describe("agentic identity: list", () => {
  it("throws, because it is the one endpoint the namespacing fold does not guard", async () => {
    const { client } = newFakeClient();
    await expect(primitivesFor(client).list()).rejects.toThrow(
      /unguarded enumeration primitive/
    );
  });
});
