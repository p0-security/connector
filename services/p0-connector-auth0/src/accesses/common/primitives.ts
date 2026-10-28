import { ConnectorError } from "@p0security/connector";

/**
 * The one policy P0 sends. Any other count is `unknown`: P0 always sends
 * exactly one, so this is a P0 bug the requestor can't correct.
 */
export const onePolicy = <Policy>(
  policies: Policy[],
  { requestId, access }: { requestId: string; access: string }
): Policy => {
  const [policy, ...others] = policies;
  if (policy === undefined || others.length > 0) {
    throw new ConnectorError({
      type: "unknown",
      message: `Expected exactly 1 policy for an Auth0 ${access}, got ${policies.length}`,
      payload: { requestId, nPolicies: policies.length },
    });
  }
  return policy;
};

/**
 * The user primitives every access shares. The user is the requestor's P0
 * email, and nothing is looked up or created: P0 never creates Auth0 users.
 */
export const emailUserPrimitives = {
  // The perimeter's own check can't tell a grant from a revoke, and `list`
  // never runs it.
  validation: () => ({ user: null }),

  // Never `null`, and nothing is looked up: P0 calls this on a revoke too,
  // and can't say which it is.
  getUser: async (_context: unknown, email: string) => email,

  // Never reached, since `getUser` never returns `null`.
  createUser: async (_context: unknown, email: string) => email,

  // A deliberate no-op. `setPoliciesForUser` with a `null` policy already
  // took back what P0 gave, and the Auth0 user was there before P0.
  deleteUser: async () => {},
};
