import { z } from "zod";

import { TEAM_ROLES } from "../../github/api.ts";
import {
  appCredentials,
  login,
  newAccessSpec,
  newGitHubId,
  userQueries,
} from "../common/definition.ts";

// A team's slug, which GitHub derives from the team's name. GitHub doesn't
// document which characters a slug can hold, so this refuses only what could
// change which URL a call reaches, where the slug becomes a path segment: a
// `/`, whitespace, and the dot segments `.` and `..`.
const team = z
  .string()
  .regex(/^[^/\s]+$/, "must be a GitHub team slug")
  .refine(
    (slug) => slug !== "." && slug !== "..",
    "must be a GitHub team slug"
  );

// The team's id: the id behind a slug. A team's maintainers can rename it,
// which changes its slug, and another team can then take the old one. So a
// requestor names a team by its slug, and the connector acts on its id.
const teamId = newGitHubId("must be a GitHub team id");

// The membership to leave the user with on one team: `member`, `maintainer`,
// or `null` for none at all. A grant sends the requested role, and a revoke
// the membership the user had before the grant, so `null` when they weren't
// on the team.
const policy = z.object({ teamId, role: z.enum(TEAM_ROLES).nullable() });

// Like the `role` access's lister, with the lookups in `userQueries`. `team`
// lists the org's teams, `{ key: <slug>, value: <name> }`. The other two
// aren't listings, and return `[]` or one item. `team-id` reads the id behind
// a slug, `{ key: <id>, value: <slug> }`, for the policy's `teamId`.
// `team-membership` reads the role of one user's own membership of one team,
// for the prior membership and the check for an existing grant.
const listerQuery = z.discriminatedUnion("type", [
  z.object({ type: z.literal("team"), context: appCredentials }),
  z.object({ type: z.literal("team-id"), context: appCredentials, team }),
  z.object({
    type: z.literal("team-membership"),
    context: appCredentials,
    teamId,
    login,
  }),
  ...userQueries,
]);

export const spec = newAccessSpec(policy, listerQuery);
