import { z } from "zod";

/**
 * The ids and keys the connector sends LaunchDarkly. Most become a URL path
 * segment, so each is held to a shape with no room for a `/`, a `?` or a
 * `.`-only name, before the client encodes it again (`segment` in
 * launchdarkly/api.ts).
 */

// LaunchDarkly's ids are letters and digits. The spec's examples are all
// 24-character hex ObjectIds, which this allows. It doesn't require that
// shape, so an id LaunchDarkly mints another way still parses.
const ID_PATTERN = /^[A-Za-z0-9]{1,64}$/;

/**
 * A member's `_id`. `me` is refused in any case: `GET` and
 * `PATCH /members/{id}` read it as the caller, the token's own member.
 */
export const memberId = z
  .string()
  .regex(ID_PATTERN, { abort: true, error: "must be a LaunchDarkly member id" })
  .refine(
    (id) => id.toLowerCase() !== "me",
    "must be a member's own id, not `me`"
  );

/**
 * The principal's email, as P0 holds it. Not `z.email()` on purpose: the
 * connector decides which emails it accepts, against its own domain
 * allowlist, and refuses the rest with a message the requester reads.
 * Parsing the shape here would turn that refusal into a bad request.
 */
export const email = z.string().min(1);
