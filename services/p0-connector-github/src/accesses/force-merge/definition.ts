import { z } from "zod";

import {
  appCredentials,
  login,
  newAccessSpec,
  repo,
  userQueries,
} from "../common/definition.ts";

/**
 * Whether `name` is a name `git check-ref-format --branch` accepts: no control
 * characters, spaces or any of `~^:?*[\`, no `..` or `@{`, not `@` alone, no
 * leading `-`, and every `/`-separated component non-empty, not starting with
 * `.` and not ending in `.lock`, with no trailing `.`.
 */
const isBranchName = (name: string) =>
  // eslint-disable-next-line no-control-regex
  !/[\x00-\x20\x7f~^:?*[\\]/.test(name) &&
  !name.includes("..") &&
  !name.includes("@{") &&
  name !== "@" &&
  !name.startsWith("-") &&
  !name.endsWith(".") &&
  name
    .split("/")
    .every(
      (component) =>
        component !== "" &&
        !component.startsWith(".") &&
        !component.endsWith(".lock")
    );

// A branch's name. It may hold `/`, which the request helpers encode, so it
// stays one path segment, and none of the wildcard characters a protection
// rule's pattern can use.
export const branch = z
  .string()
  .refine(isBranchName, "must be a Git branch name");

// The end state of the user's bypass of one branch's required reviews:
// `allowed` puts them on the branch's bypass list, and `false` takes them off
// it. A grant sends `true`, and a revoke what the user had before the grant,
// so `false` unless they were already on the list.
const policy = z.object({ repo, branch, allowed: z.boolean() });

// Like the `team` access's lister, with the lookups in `userQueries`.
// `bypass-allowance` isn't a listing, and returns `[]` or one item: whether
// one user is on one branch's bypass list, for the prior state and the check
// for an existing grant. `protected-branch` lists the branches of one repo
// that force-merge access can be granted on, `{ key: <branch>, value:
// <branch> }`.
const listerQuery = z.discriminatedUnion("type", [
  z.object({
    type: z.literal("bypass-allowance"),
    context: appCredentials,
    repo,
    branch,
    login,
  }),
  z.object({
    type: z.literal("protected-branch"),
    context: appCredentials,
    repo,
  }),
  ...userQueries,
]);

export const spec = newAccessSpec(policy, listerQuery);
