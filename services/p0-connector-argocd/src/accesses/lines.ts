/**
 * Grants and revokes as the connector makes them: one `g` line in
 * `policy.p0.csv`, added or removed by a merge patch of `argocd-rbac-cm`
 * through the Application that manages it. Both accesses run through here,
 * each with its own {@link Grant}.
 *
 * Read, change, write isn't atomic, and the patch isn't made conditional on
 * the ConfigMap's `resourceVersion`: what keeps two writes to one instance
 * apart is P0's lock on the instance, taken around every call that writes.
 */
import {
  ConnectorError,
  type Logger,
  throwAssertNever,
} from "@p0security/connector-core";

import { assertAllowedEmail } from "../allowlist.ts";
import {
  type ArgoCdClient,
  type ArgoCdProject,
  type ConnectArgoCd,
  P0_POLICY_KEY,
  type RbacTarget,
  rbacTargetOf,
} from "../argocd/client.ts";
import { callArgoCd } from "../argocd/errors.ts";
import {
  type Grant,
  type P0Line,
  PolicyLineError,
  type RbacPolicy,
  addLine,
  buildLine,
  holds,
  parsePolicy,
  removeLine,
} from "../argocd/policy.ts";
import { type ArgoCdRoles, listRoles } from "../argocd/roles.ts";
import type { Instance } from "../instance.ts";
import { refusal } from "../refusals.ts";
import { assertLeastPrivilege } from "../self-check.ts";
import { hostOf } from "./common.ts";

/** What the connector read of an instance's policy. */
export type InstancePolicy = {
  /** `argocd-rbac-cm`'s keys, as read. */
  data: Record<string, string>;
  /** Every policy key, `policy.p0.csv` included: what Argo CD enforces. */
  policy: RbacPolicy;
  /**
   * The roles the customer's own keys define: `policy.p0.csv` left out, so
   * a role named only by a line P0 wrote isn't offered or granted.
   */
  roles: ArgoCdRoles;
  /** `policy.default`, if any: the role every user holds. */
  defaultRole: string | undefined;
};

/** `data` without the key the connector writes. */
const customerData = (data: Record<string, string>) =>
  Object.fromEntries(
    Object.entries(data).filter(([key]) => key !== P0_POLICY_KEY)
  );

/**
 * Reads `argocd-rbac-cm` and, with `projects`, the AppProjects, as the
 * account. Call `userInfo` first.
 */
export const readInstancePolicy = async (
  argocd: ArgoCdClient,
  target: RbacTarget,
  { projects: withProjects }: { projects: boolean }
): Promise<InstancePolicy> => {
  const [{ data }, projects] = await Promise.all([
    argocd.readRbacConfigMap(target),
    withProjects ? argocd.listProjects() : Promise.resolve<ArgoCdProject[]>([]),
  ]);
  const policy = parsePolicy({ data }, projects);
  return {
    data,
    policy,
    roles: listRoles(parsePolicy({ data: customerData(data) }, projects)),
    defaultRole: policy.defaultRole,
  };
};

/** Whether `policy.p0.csv`'s value has `line`, as Argo CD reads a line. */
const hasLine = (value: string | undefined, line: P0Line) =>
  addLine(value, line) === (value ?? "");

/**
 * Connects to the instance and proves the token: `userInfo` fails with
 * `anonymous` for one Argo CD didn't accept, before any call whose answer an
 * anonymous caller could get.
 */
const connectAs = async (
  connect: ConnectArgoCd,
  instance: Instance,
  log: Logger
) => {
  const argocd = await connect(instance, log);
  await callArgoCd(() => argocd.userInfo(), hostOf(instance));
  return argocd;
};

/**
 * The error for a patch Argo CD accepted but a read straight after doesn't
 * show. `found` completes "policy.p0.csv ...".
 */
const notApplied = (
  host: string,
  { found, retry }: { found: string; retry: "grant" | "revoke" }
) =>
  new ConnectorError({
    type: "dependency_violation",
    message: `Argo CD at ${host} accepted the change to ${P0_POLICY_KEY} in argocd-rbac-cm, but reading it back, ${P0_POLICY_KEY} ${found}. Check argocd-rbac-cm, then retry the ${retry}.`,
    payload: { host },
  });

/** The refusal for a policy Argo CD won't load, naming where, never what. */
export const policyNotLoaded = (host: string, policy: RbacPolicy) => {
  const where = policy.refusedLines.map(
    ({ key, line }) => `${key} line ${line}`
  );
  return refusal({
    reason: "policy_not_loaded",
    message: `argocd-rbac-cm on Argo CD at ${host} has a line Argo CD refuses (${where.join(", ")}), so Argo CD keeps enforcing the policy it had before it, and a new line wouldn't take effect. Fix or remove that line.`,
    payload: { host, lines: where.join("; ") },
  });
};

/** The refusal for a grant the line's own rules refuse. */
const lineRefused = (
  error: PolicyLineError,
  { host, email, grant }: { host: string; email: string; grant: Grant }
) => {
  switch (error.reason) {
    case "connector_role":
      return refusal({
        reason: "connector_role",
        message: `P0 never grants ${grant.role}, the connector's own role.`,
        payload: { host, role: grant.role },
      });
    case "email":
      return refusal({
        reason: "not_an_email",
        message: `${email} isn't an email the Argo CD connector can grant a role to.`,
        payload: { host },
      });
    // The access's schema holds the role and the project to the line's
    // rules, so these come only from a schema that drifted from them. A
    // role that can't be written can't be on the instance either.
    case "project":
    case "role":
      return refusal({
        reason: "role_not_found",
        message: `Argo CD at ${host} has no role P0 can grant by that name.`,
        payload: { host },
      });
    default:
      throw throwAssertNever(error.reason);
  }
};

/** What a grant or a revoke acts on. */
export type LineRequest = {
  connect: ConnectArgoCd;
  /** Bound to the request, the host and the grant. Never the email. */
  log: Logger;
  instance: Instance;
  email: string;
  grant: Grant;
};

/**
 * Gives the user `grant`'s role, by adding P0's line for it to
 * `policy.p0.csv`. In order:
 *
 * 1. the domain allowlist, before the secret is read or Argo CD is called;
 * 2. the line's own refusals: the connector's role, an email P0 doesn't
 *    write;
 * 3. `userInfo`, which refuses a token Argo CD answers as anonymous, then
 *    the privilege self-check;
 * 4. `argocd-rbac-cm` and the AppProjects, read once;
 * 5. `refuseMissing`, the access's own check that the role exists;
 * 6. P0's own line there already is success, with no write: a retried grant;
 * 7. a line Argo CD refuses anywhere refuses the grant, since the new line
 *    wouldn't take effect;
 * 8. the role held any other way refuses it (overlap);
 * 9. a merge patch carrying `policy.p0.csv` alone, then a read that shows
 *    the line.
 */
export const grantLine = async (
  { connect, log, instance, email, grant }: LineRequest,
  refuseMissing: (read: InstancePolicy) => void
): Promise<void> => {
  const host = hostOf(instance);
  assertAllowedEmail(email, log);
  let line: P0Line;
  try {
    line = buildLine(email, grant);
  } catch (error) {
    if (error instanceof PolicyLineError) {
      throw lineRefused(error, { host, email, grant });
    }
    throw error;
  }
  const argocd = await connectAs(connect, instance, log);
  const target = rbacTargetOf(instance);
  await callArgoCd(async () => {
    await assertLeastPrivilege(argocd, host);
    const read = await readInstancePolicy(argocd, target, { projects: true });
    refuseMissing(read);
    const current = read.data[P0_POLICY_KEY];
    if (hasLine(current, line)) {
      log.info("P0's line is in policy.p0.csv already; nothing to write");
      return;
    }
    if (read.policy.refusedLines.length > 0) {
      throw policyNotLoaded(host, read.policy);
    }
    if (holds(read.policy, email, grant)) {
      throw refusal({
        reason: "already_held",
        message: `${email} already holds ${describeGrant(grant)} on Argo CD at ${host}.`,
        payload: { host, ...grant },
      });
    }
    await argocd.patchRbacConfigMap(target, {
      [P0_POLICY_KEY]: addLine(current, line),
    });
    log.info("added P0's line to policy.p0.csv");
    const after = await argocd.readRbacConfigMap(target);
    if (!hasLine(after.data[P0_POLICY_KEY], line)) {
      throw notApplied(host, {
        found: "doesn't have the line",
        retry: "grant",
      });
    }
  }, host);
};

/**
 * Takes `grant`'s role back, by removing P0's line for it from
 * `policy.p0.csv`. Only that exact line goes: a line someone else wrote is
 * left, even one that grants the same.
 *
 * It never checks the domain allowlist or the account's privileges: taking
 * access away mustn't depend on either. A line that isn't there is success,
 * and so is a line P0 would never have written. It goes ahead when
 * `argocd-rbac-cm` has a line Argo CD refuses: the removal is right whatever
 * Argo CD enforces now.
 */
export const revokeLine = async ({
  connect,
  log,
  instance,
  email,
  grant,
}: LineRequest): Promise<void> => {
  const host = hostOf(instance);
  let line: P0Line;
  try {
    line = buildLine(email, grant);
  } catch (error) {
    if (!(error instanceof PolicyLineError)) throw error;
    log.info(
      { refused: error.reason },
      "P0 never writes a line for this grant; nothing to revoke"
    );
    return;
  }
  const argocd = await connectAs(connect, instance, log);
  const target = rbacTargetOf(instance);
  await callArgoCd(async () => {
    const { data } = await argocd.readRbacConfigMap(target);
    const current = data[P0_POLICY_KEY];
    if (!hasLine(current, line)) {
      log.info("P0's line isn't in policy.p0.csv; already revoked");
      return;
    }
    await argocd.patchRbacConfigMap(target, {
      [P0_POLICY_KEY]: removeLine(current, line),
    });
    log.info("removed P0's line from policy.p0.csv");
    const after = await argocd.readRbacConfigMap(target);
    if (hasLine(after.data[P0_POLICY_KEY], line)) {
      throw notApplied(host, { found: "still has the line", retry: "revoke" });
    }
  }, host);
};

/** `role:admin`, or `the deployer role on project payments`, for a message. */
export const describeGrant = (grant: Grant) =>
  grant.kind === "global"
    ? grant.role
    : `the ${grant.role} role on project ${grant.project}`;

/**
 * Whether the user with `email` holds `grant`'s role, for the `held` lister:
 * the allowlist first, then `argocd-rbac-cm` and the AppProjects. Every
 * policy key counts, P0's own included.
 */
export const readHeld = async (
  connect: ConnectArgoCd,
  log: Logger,
  instance: Instance,
  email: string,
  grant: Grant
): Promise<boolean> => {
  assertAllowedEmail(email, log);
  const host = hostOf(instance);
  const argocd = await connectAs(connect, instance, log);
  return await callArgoCd(async () => {
    const { policy } = await readInstancePolicy(
      argocd,
      rbacTargetOf(instance),
      { projects: true }
    );
    return holds(policy, email, grant);
  }, host);
};

/**
 * The roles the customer's own keys define, for the role listers. With
 * `projects`, each AppProject's roles too.
 */
export const readRoles = async (
  connect: ConnectArgoCd,
  log: Logger,
  instance: Instance,
  { projects }: { projects: boolean }
): Promise<ArgoCdRoles> => {
  const host = hostOf(instance);
  const argocd = await connectAs(connect, instance, log);
  return await callArgoCd(
    async () =>
      (
        await readInstancePolicy(argocd, rbacTargetOf(instance), {
          projects,
        })
      ).roles,
    host
  );
};
