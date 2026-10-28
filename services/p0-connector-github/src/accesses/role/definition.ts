import { z } from "zod";

import {
  appCredentials,
  login,
  newAccessSpec,
  repo,
  userQueries,
} from "../common/definition.ts";

// The direct collaborator role to leave the user with on one repository. The
// role is in the form PUT accepts: `pull`, `triage`, `triage_plus`, `push`,
// `maintain`, `admin`, or a custom role's name. `null` is no direct role at
// all. A grant sends the requested role, and a revoke the role the user held
// before the grant, so `null` when they had none.
const policy = z.object({ repo, role: z.string().min(1).nullable() });

// `list` gets no request context, so every query carries the credentials, as
// its `context`. A lookup's own fields sit beside it. `direct-role` isn't a
// listing, and returns `[]` or one item, like the lookups in `userQueries`. It
// reads one user's direct role on one repo, for the prior role and the check
// for an existing grant. `repository-id` reads the id behind a repository's
// name, `{ key: <id>, value: <name> }`, so P0 can tell two requests are for
// one repository after it's renamed.
const listerQuery = z.discriminatedUnion("type", [
  z.object({ type: z.literal("repository"), context: appCredentials }),
  z.object({ type: z.literal("role"), context: appCredentials }),
  z.object({
    type: z.literal("direct-role"),
    context: appCredentials,
    repo,
    login,
  }),
  ...userQueries,
  z.object({ type: z.literal("repository-id"), context: appCredentials, repo }),
]);

export const spec = newAccessSpec(policy, listerQuery);
