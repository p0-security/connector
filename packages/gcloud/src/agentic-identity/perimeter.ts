/**
 * The agentic identity lifecycle, expressed as resource-root connector
 * primitives.
 *
 * The "user" is the short-lived GCP service account P0 mints for one agentic
 * session; the "policies" are the federated principal allowed to impersonate
 * it, and until when. Nothing here names Google Drive, or any other target
 * system — the identity is minted in a project and handed back as an address,
 * which is what lets a second Workspace integration reuse it unchanged.
 *
 * The user body says everything about the account: which project, which id,
 * and which subject it stands for. The request context carries only what the
 * framework's id-keyed calls need to re-check an address against its project.
 *
 * This module deliberately does not import the connector framework: the
 * framework already depends on `@p0security/connector-gcloud-common`, so the dependency
 * only runs one way. The types below restate the framework's resource-root
 * contract structurally, and the service that mounts the router is where the
 * two are checked against each other.
 */
import type { cloudresourcemanager_v3 } from "@googleapis/cloudresourcemanager";

import type { GcloudClients } from "../client.ts";
import { ProxyError, ValidationError } from "../errors.ts";
import { getOrgId } from "../helpers/ancestry.ts";
import logger from "../logger.ts";
import { newMemberVerifier } from "../member-verify.ts";
import { PolicyRouter } from "../policy-router.ts";
import type {
  GcloudPolicyResourceWithProject,
  GcloudServiceMetadata,
} from "../types.ts";
import {
  agenticIdentityEmail,
  isAgenticIdentityAccountId,
  isAgenticIdentityEmail,
  isAgenticIdentitySubject,
  isProjectId,
} from "./naming.ts";

/** The role that grants impersonation of a service account. The only role this
 * perimeter ever writes. */
const WORKLOAD_IDENTITY_USER_ROLE = "roles/iam.workloadIdentityUser";

const CONDITION_DESCRIPTION = "Impersonation window for a P0 agentic identity.";

/** An RFC 3339 instant, which is the subset of ISO 8601 that CEL's
 * `timestamp()` accepts. */
const ISO_8601_INSTANT =
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?(Z|[+-]\d{2}:\d{2})$/;

/** Per-call context. `project` is what an id-keyed call (delete, converge)
 * checks the address against: those calls see a user id, never a body. */
export type AgenticIdentityRequestContext = {
  requestId: string;
  project: string;
};

/** The service account to find or create.
 *
 * `project` and `accountId` are the address. `subject` is the federated subject
 * the account stands for; it is carried so the perimeter can refuse a body
 * whose subject is outside P0's namespace, and it is written into the
 * account's description so a customer reading their IAM console can tell which
 * session an account belongs to. */
export type AgenticIdentityUserBody = {
  project: string;
  accountId: string;
  subject: string;
};

/** Who may impersonate the identity, and until when.
 *
 * `member` is the federated principal, as IAM writes it. `expiresAt` is an ISO
 * 8601 instant and becomes an IAM condition on the binding; absent means the
 * binding carries no condition. */
export type AgenticIdentityPolicy = {
  member: string;
  expiresAt?: string;
};

/** Everything a request needs from GCP, resolved once per call. */
export type AgenticIdentityConnection = {
  client: GcloudClients;
  metadata: GcloudServiceMetadata;
};

const statusOf = (error: any): number | undefined =>
  error?.code ?? error?.status ?? error?.response?.status;

/** The IAM resource an identity's impersonation policy lives on: the service
 * account itself. */
const policyTarget = (
  project: string,
  emailAddress: string
): GcloudPolicyResourceWithProject => ({
  type: "serviceaccount",
  name: emailAddress,
  projectId: project,
});

/** Builds the condition for one expiry group.
 *
 * `expiresAt` is interpolated into a CEL expression, so it is checked against
 * an anchored instant pattern first — a value carrying a quote could otherwise
 * close the `timestamp()` literal and rewrite the condition it is meant to
 * constrain.
 */
const expiryCondition = (
  expiresAt: string
): cloudresourcemanager_v3.Schema$Expr => {
  if (!ISO_8601_INSTANT.test(expiresAt) || isNaN(Date.parse(expiresAt))) {
    throw new ValidationError(
      `'${expiresAt}' is not an ISO 8601 instant and cannot be used as an expiry.`
    );
  }
  return {
    title: `p0-agentic-identity-expires-${expiresAt}`,
    description: CONDITION_DESCRIPTION,
    expression: `request.time < timestamp("${expiresAt}")`,
  };
};

/** Folds a policy set into the bindings that must exist afterwards.
 *
 * An empty policy set folds to no bindings, which is how the role comes to be
 * absent. Otherwise there is exactly one binding, holding the one member this
 * identity has, conditioned on the expiry if the policy carries one.
 */
const desiredBindings = (
  policies: AgenticIdentityPolicy[]
): cloudresourcemanager_v3.Schema$Binding[] => {
  // A group that reaches here uncollapsed is a control-plane bug, not a
  // customer error, so it is thrown as an internal failure rather than guessed
  // at: an identity has one member, and two expiries for it cannot both hold.
  if (policies.length > 1) {
    throw new Error(
      `Expected at most one policy for an agentic identity, got ${policies.length}.`
    );
  }

  const policy = policies[0];
  if (!policy) return [];

  const binding: cloudresourcemanager_v3.Schema$Binding = {
    role: WORKLOAD_IDENTITY_USER_ROLE,
    members: [policy.member],
  };
  if (policy.expiresAt) binding.condition = expiryCondition(policy.expiresAt);
  return [binding];
};

/**
 * Builds the resource-root primitives for P0 agentic identities.
 *
 * @param connect Resolves the GCP clients and this service's own metadata.
 * Called once per request rather than once per process, so a router can mount
 * these primitives without waiting on the metadata server at startup.
 */
export const newAgenticIdentityPrimitives = (
  connect: () => Promise<AgenticIdentityConnection>
) => {
  /** The address the body names, whether or not it exists yet. */
  const addressOf = (userBody: AgenticIdentityUserBody) =>
    agenticIdentityEmail(userBody.accountId, userBody.project);

  // Re-checked here rather than trusted from the framework's namespacing fold:
  // these primitives are what actually reach IAM, and an address outside P0's
  // namespace means writing to a service account this perimeter did not mint.
  const assertNamespaced = (
    context: AgenticIdentityRequestContext,
    userId: string
  ) => {
    if (!isAgenticIdentityEmail(userId, context.project)) {
      throw new ValidationError(
        `Service account '${userId}' is not a P0 agentic identity in project '${context.project}'.`
      );
    }
  };

  const orgIdOf = async (
    client: GcloudClients,
    projectId: string
  ): Promise<string | undefined> => {
    try {
      return await getOrgId(client, projectId);
    } catch (error: any) {
      throw new ProxyError(
        "gcloud",
        `Error resolving the organization of project '${projectId}'.`,
        error
      );
    }
  };

  /** Checked once, before creation: the identity project must sit in the same
   * organization as the perimeter itself. Minting principals in a project
   * outside the customer's own organization is not something this service
   * should ever be asked to do. */
  const assertEligible = async (
    connection: AgenticIdentityConnection,
    project: string
  ) => {
    const { client, metadata } = connection;
    if (project === metadata.projectId) return;
    const [orgId, targetOrgId] = await Promise.all([
      orgIdOf(client, metadata.projectId),
      orgIdOf(client, project),
    ]);
    if (!orgId || !targetOrgId || orgId !== targetOrgId) {
      throw new ValidationError(
        `Project '${project}' does not belong to an organization under this account.`
      );
    }
  };

  const readServiceAccount = async (
    client: GcloudClients,
    project: string,
    emailAddress: string
  ) => {
    try {
      const { data } = await client.iam.projects.serviceAccounts.get({
        name: `projects/${project}/serviceAccounts/${emailAddress}`,
      });
      return data;
    } catch (error: any) {
      // A deleted account still in GCP's undelete window answers `get` by email
      // with a 403, not a 404, even to a caller holding `iam.serviceAccounts.get`
      // on the project. Addresses are keyed on the session, so a grant after the
      // session's identity was torn down lands on exactly that address. Reading
      // it as absent lets `createUser` mint a fresh account there; a caller that
      // genuinely lacks permission is refused by `create` instead.
      const status = statusOf(error);
      if (status === 404 || status === 403) return undefined;
      throw new ProxyError(
        "gcloud",
        `Error reading agentic identity '${emailAddress}'.`,
        error
      );
    }
  };

  return {
    validation: (context: AgenticIdentityRequestContext) => ({
      user: {
        userIsNamespacedById: async (userId: string) =>
          isAgenticIdentityEmail(userId, context.project),
        // The body is authoritative for provisioning, but the id-keyed calls
        // that follow check addresses against `context.project`. A body naming
        // a different project would provision an account those calls then
        // refuse to touch, so the disagreement is refused up front.
        userIsNamespacedByBody: async (userBody: AgenticIdentityUserBody) =>
          isAgenticIdentitySubject(userBody.subject) &&
          isAgenticIdentityAccountId(userBody.accountId) &&
          isProjectId(userBody.project) &&
          userBody.project === context.project,
      },
    }),

    getUser: async (
      _context: AgenticIdentityRequestContext,
      userBody: AgenticIdentityUserBody
    ): Promise<string | null> => {
      const emailAddress = addressOf(userBody);
      const { client } = await connect();
      const existing = await readServiceAccount(
        client,
        userBody.project,
        emailAddress
      );
      return existing ? emailAddress : null;
    },

    createUser: async (
      context: AgenticIdentityRequestContext,
      userBody: AgenticIdentityUserBody
    ): Promise<string> => {
      const emailAddress = addressOf(userBody);
      const connection = await connect();
      await assertEligible(connection, userBody.project);

      try {
        await connection.client.iam.projects.serviceAccounts.create({
          name: `projects/${userBody.project}`,
          requestBody: {
            accountId: userBody.accountId,
            serviceAccount: {
              displayName: "P0 agentic identity",
              description: `Minted by the P0 security perimeter for agentic session subject '${userBody.subject}'.`,
            },
          },
        });
      } catch (error: any) {
        // Every grant names a fresh random address, so an account already
        // holding it was not created for this grant. Adopting it would let
        // this grant's binding replace another grant's.
        if (statusOf(error) === 409) {
          throw new ValidationError(
            `Agentic identity '${emailAddress}' already exists and was not created for this grant.`
          );
        }
        throw new ProxyError(
          "gcloud",
          `Error creating agentic identity '${emailAddress}'.`,
          error
        );
      }
      logger.info(
        { requestId: context.requestId, emailAddress },
        "Agentic identity created"
      );
      return emailAddress;
    },

    // Deleted, not disabled: the subject carries the session, so disabling
    // would accumulate one dormant account per session forever and would need
    // a sweeper — which would need list and delete permissions back anyway.
    deleteUser: async (
      context: AgenticIdentityRequestContext,
      userId: string
    ): Promise<void> => {
      assertNamespaced(context, userId);
      const { client } = await connect();
      try {
        await client.iam.projects.serviceAccounts.delete({
          name: `projects/${context.project}/serviceAccounts/${userId}`,
        });
      } catch (error: any) {
        if (statusOf(error) === 404) {
          logger.info(
            { requestId: context.requestId, userId },
            "Agentic identity already absent; nothing to delete"
          );
          return;
        }
        throw new ProxyError(
          "gcloud",
          `Error deleting agentic identity '${userId}'.`,
          error
        );
      }
      logger.info(
        { requestId: context.requestId, userId },
        "Agentic identity deleted"
      );
    },

    /**
     * Converges `roles/iam.workloadIdentityUser` on the identity so its members
     * are exactly the single policy's member, under the condition that policy
     * asks for. An empty policy set removes the role from the service account
     * altogether.
     */
    setPoliciesForUser: async (
      context: AgenticIdentityRequestContext,
      userId: string,
      _userBody: AgenticIdentityUserBody,
      policies: AgenticIdentityPolicy[]
    ): Promise<void> => {
      assertNamespaced(context, userId);
      const { client, metadata } = await connect();

      // Folded first, so a malformed set is refused before anything is read.
      const bindings = desiredBindings(policies);

      // Verified before anything is read or written — the member is what the
      // perimeter is being asked to trust, and it is supplied by the control
      // plane, which the perimeter does not take on faith. An empty set has no
      // member to verify, and writes nothing but the role's absence.
      const memberVerifier = newMemberVerifier(client, metadata);
      for (const { member } of policies) {
        await memberVerifier.verifyMember(member);
      }

      const target = policyTarget(context.project, userId);
      const policyRouter = PolicyRouter(client);
      const policy = await policyRouter.getPolicy(target);

      // Replace rather than amend. Amending, by matching an existing binding on
      // its role, title and expression, would miss a re-grant with a longer
      // expiry, so it would append a second binding and leave the first one
      // granting until its own expiry; removing by title alone would then not
      // find it. Every binding of this role on a P0-minted service account is
      // P0's, so dropping them all and re-adding the desired set is what makes
      // the result exactly the requested set — and, when the set is empty, no
      // set at all.
      const retained = (policy.bindings ?? []).filter(
        (binding) => binding.role !== WORKLOAD_IDENTITY_USER_ROLE
      );
      policy.bindings = [...retained, ...bindings];

      await policyRouter.setPolicy(context.project, policy, target);
      logger.info(
        {
          requestId: context.requestId,
          userId,
          nBindings: bindings.length,
        },
        "Converged agentic identity impersonation policy"
      );
    },

    /** Always throws.
     *
     * `list` is mounted unconditionally by the framework and is the one
     * endpoint its namespacing fold does not guard, so a working implementation
     * here would be an unguarded enumeration primitive inside the perimeter.
     */
    list: async (): Promise<never> => {
      throw new ValidationError(
        "Listing is not available on the agentic identity perimeter: `list` is " +
          "mounted unconditionally and is not covered by the framework's " +
          "namespacing guards, so implementing it would expose an unguarded " +
          "enumeration primitive inside the perimeter."
      );
    },
  };
};
