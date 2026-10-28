import type {
  AnyConnectorTRPCInstance,
  ConnectorContext,
  Logger,
  ResourceRootConnectorPrimitives,
  ResourceRootSchemaOf,
} from "@p0security/connector";
import { ConnectorError, newResourceRootRouter } from "@p0security/connector";
import { isAgenticIdentityEmail } from "@p0security/gcloud-common";

import type { DriveApi, DrivePermission } from "../../drive/api.ts";
import { newDriveApi } from "../../drive/api.ts";
import { newDriveClient } from "../../drive/client.ts";
import { callDrive } from "../../drive/errors.ts";
import { spec } from "./definition.ts";

type ResourceSchema = ResourceRootSchemaOf<typeof spec>;
type RequestContext = ResourceSchema["RequestContext"];

const FOLDER_MIME_TYPE = "application/vnd.google-apps.folder";

/** The roles this connector is capable of setting, and therefore the only ones
 * it is willing to find already on an entry it is about to converge. */
const SETTABLE_ROLES: readonly string[] = ["reader", "writer"];

/**
 * Drive answers 404 both for an item that does not exist and for one in a drive
 * this connector cannot see. It cannot tell them apart, so it does not claim
 * to. `payload.query` carries the id, and `object_not_found` is one of the
 * error types whose message reaches the requestor.
 */
const notFound = (requestId: string, resourceId: string) =>
  new ConnectorError({
    type: "object_not_found",
    message: `Drive item '${resourceId}' was not found in any shared drive this connector manages`,
    payload: { requestId, query: resourceId },
  });

/**
 * Asserts that the item about to be written is the item the request was
 * approved against.
 *
 * Containment is an I/O precondition, not a predicate: resource root's
 * `validation` has no resource-side slot, and Drive ids are opaque, so there is
 * nothing to test syntactically. Without this read, a request approved against
 * drive A could grant into drive B — both installed, so the blast radius stays
 * inside the install, but the policy that was evaluated was drive A's.
 *
 * The drive root is excluded because a `permissions.create` on a drive id is a
 * *membership* mutation, and Drive silently swallows a concurrent folder grant
 * to a principal that is already a member — a write the control plane believes
 * landed, which the resource-root union cannot repair.
 */
const assertContained = async (
  api: DriveApi,
  { requestId, driveId }: RequestContext,
  resourceId: string
) => {
  const file = await callDrive(() => api.getFile(resourceId), {
    requestId,
    query: resourceId,
  });
  if (!file) throw notFound(requestId, resourceId);
  if (file.driveId !== driveId) {
    throw new ConnectorError({
      type: "validation_error",
      // Deliberately does not name the drive the item is actually in: the
      // requestor was not approved for it and has no business learning of it.
      message: `Drive item '${resourceId}' is not in the shared drive this request was approved against`,
      payload: { requestId, driveId, resourceId },
    });
  }
  if (file.id === driveId) {
    throw new ConnectorError({
      type: "validation_error",
      message:
        "A shared drive itself cannot be granted; name a folder or file inside it",
      payload: { requestId, driveId, resourceId },
    });
  }
  return file;
};

const entryFor = (
  permissions: DrivePermission[],
  emailAddress: string
): DrivePermission | undefined => {
  const address = emailAddress.toLowerCase();
  return permissions.find(
    (permission) => permission.emailAddress?.toLowerCase() === address
  );
};

/**
 * The Google Drive grant path.
 *
 * One `permissions.create` per grant, on the requested folder or file, made by
 * the connector's own service identity — which holds `organizer` standing on
 * every registered shared drive, established by a human at install. There is no
 * membership mutation and no second credential.
 *
 * The grantee is a service account P0 mints per grant; it is never a
 * member of the drive, so a role on an item is an actual grant rather than a
 * floor over inherited membership.
 *
 * Exported separately from {@link router} so the primitives can be driven
 * against a {@link DriveApi} double.
 */
export const newDriveResourcePrimitives = (
  logger: Logger,
  api: DriveApi
): ResourceRootConnectorPrimitives<ResourceSchema> => ({
  validation: (context) => {
    // The guard that stops a human's email address reaching a Drive ACL, which
    // a Drive ACL would otherwise happily accept — `user` plus an address is
    // exactly the shape a human principal takes there. The framework runs it on
    // every provision, identify, delete and policy write, and it cannot be
    // skipped from the wire.
    //
    // The shape is the shared one rather than a regex spelled a second time
    // here. `p0a-` and `.iam.gserviceaccount.com` are deployed-code constants,
    // so no control-plane bug can widen them, and only the project can
    // mint addresses in its own namespace — which makes this stronger than a
    // prefix convention. Comparing the domain by equality rather than by
    // interpolating the project into a pattern also means there is no pattern
    // for the project to be escaped for.
    const isAgenticIdentity = async (address: string) =>
      isAgenticIdentityEmail(address, context.projectId);
    return {
      user: {
        userIsNamespacedById: isAgenticIdentity,
        userIsNamespacedByBody: isAgenticIdentity,
      },
    };
  },

  /**
   * Returns its argument unchanged.
   *
   * Drive has no user object to look up: an address either exists in IAM or it
   * does not, and this connector has no IAM reach to ask. Returning the address
   * — never null — is also what makes `createUser` below unreachable.
   */
  getUser: async (_context, username) => username,

  /**
   * Always throws.
   *
   * The framework's `provisionUser` is get-or-create and `getUser` never
   * returns null, so nothing reaches this. Agentic identities are created by
   * the GCP service account connector, not here. Dead code inside a
   * security perimeter is a liability, so this fails loudly and says why rather
   * than quietly doing something plausible.
   */
  createUser: (context, username) => {
    throw new ConnectorError({
      type: "unknown",
      message:
        "The Google Drive (Agentic) connector cannot create identities; the grantee service account is created by P0's GCP service account connector before the grant runs",
      payload: { requestId: context.requestId, username },
    });
  },

  /**
   * A no-op, and this is load-bearing.
   *
   * The framework calls this when a request has no siblings *on the same item*.
   * But one agentic identity is shared across a session's grants to *different*
   * items, which are not siblings by that definition — so destroying the
   * identity here would break a live grant somewhere else in the same session.
   * The identity's teardown is the agentic-identity delegate's last-one-out,
   * keyed on the session subject; this connector must not touch it.
   *
   * Revocation does not come through here either: it is
   * `setPoliciesForUser` with a `null` role, which converges to a
   * `permissions.delete`.
   */
  deleteUser: async (context, userId) => {
    logger.debug(
      { requestId: context.requestId, userId },
      "deleteUser is a no-op; the agentic identity outlives this grant"
    );
  },

  /**
   * Converges this identity's single ACL entry on the policy's item to the
   * policy's role, creating, re-roling or deleting it as needed.
   *
   * Not "add this": a `null` role deletes the entry, which is how revocation
   * is expressed. Drive permits one entry per principal per item, so the
   * control plane collapses the union of open requests to exactly one policy
   * before it gets here.
   */
  setPoliciesForUser: async (context, userId, _user, policies) => {
    const { requestId, driveId } = context;

    if (policies.length !== 1) {
      // `unknown`, not `validation_error`: the control plane always sends one
      // policy, so any other count is a P0 backend bug rather than anything
      // the requestor could correct, and must not surface to them as if it
      // were their input that was wrong.
      throw new ConnectorError({
        type: "unknown",
        message: `Expected exactly 1 policy for a Google Drive grant, got ${policies.length}`,
        payload: { requestId, nPolicies: policies.length },
      });
    }
    const [{ resourceId, role }] = policies;
    const log = logger.child({ requestId, driveId, resourceId, userId });

    await assertContained(api, context, resourceId);

    // A convergence read, not a verification one: seeing no entry means
    // "create", never "the last write failed".
    const permissions = await callDrive(() => api.listPermissions(resourceId), {
      requestId,
      query: resourceId,
    });
    const existing = entryFor(permissions, userId);

    if (existing && !SETTABLE_ROLES.includes(existing.role)) {
      // An entry this connector cannot have written — a customer who made the
      // grantee a drive member by hand, or a role inherited from above.
      // Refuse rather than proceed: deleting an inherited permission returns
      // 403, so a revoke that would fail is better discovered now, at grant
      // time, than at teardown.
      //
      // The test is the role, not Drive's `inherited` flag: an entry inherited
      // at a role this connector can itself set is indistinguishable from one
      // it wrote, and what Drive does to a direct write layered over such an
      // entry is not measured. Guessing there would trade a refusal this
      // connector can explain for one it cannot.
      throw new ConnectorError({
        type: "dependency_violation",
        message: `'${userId}' already holds the role '${existing.role}' on this item, which this connector did not grant and cannot remove`,
        payload: { requestId, resourceId, role: existing.role },
      });
    }

    const payload = { requestId, query: resourceId };

    if (!role) {
      if (!existing) {
        log.info("no permission to revoke; already converged");
        return;
      }
      await callDrive(
        () => api.deletePermission(resourceId, existing.id),
        payload
      );
      log.info("revoked the grant");
      return;
    }

    // Every branch below establishes success from the write's own response and
    // never re-reads it. Drive's ~30s propagation delay is authorization
    // reaching the *grantee's* token — a different plane from the metadata
    // commit made here as the admin identity — so a read-back would measure the
    // wrong thing, and would report a 404 it could not distinguish from a wrong
    // id anyway.
    if (!existing) {
      await callDrive(
        () => api.createPermission(resourceId, userId, role),
        payload
      );
      log.info({ role }, "granted");
      return;
    }
    if (existing.role !== role) {
      await callDrive(
        () => api.updatePermission(resourceId, existing.id, role),
        payload
      );
      log.info({ role, from: existing.role }, "changed the granted role");
      return;
    }
    log.info({ role }, "permission already at the requested role");
  },

  /**
   * Lists every folder and file in the drive, with its kind.
   *
   * Nothing listed here is trusted at grant time: `setPoliciesForUser`
   * re-checks containment against the request context.
   */
  list: async ({ context: { driveId } }) => {
    const files = await callDrive(() => api.listFiles(driveId), {
      query: driveId,
    });
    return files
      .filter(
        // Drive answers a listing scoped to one drive with that drive's items
        // only, and never with the root; checked anyway, since the root is
        // never a grant target and a listed item reads as approvable.
        (file) => file.driveId === driveId && file.id !== driveId
      )
      .map((file) => ({
        key: file.id,
        value: file.name,
        group: file.mimeType === FOLDER_MIME_TYPE ? "folder" : "file",
      }));
  },
});

// The Drive client is built once per process rather than per call: it holds the
// ADC token cache, and the connector's identity never varies by request.
let driveApi: DriveApi | undefined;
const sharedDriveApi = () => (driveApi ??= newDriveApi(newDriveClient()));

export const router = (t: AnyConnectorTRPCInstance) =>
  newResourceRootRouter<ResourceSchema>(t, spec, (ctx: ConnectorContext) =>
    newDriveResourcePrimitives(ctx.logger, sharedDriveApi())
  );
