import { z } from "zod";

import { tailnetCredentials } from "../../credentials.ts";

export const email = z.email();

/** A P0 request id: a Firestore id, letters and digits, case kept. */
export const requestId = z
  .string()
  .regex(/^[A-Za-z0-9]{1,64}$/, "must be a P0 request id");

/**
 * What `list` answers, with a read-only token. `list` gets no request
 * context, so each query carries the tailnet's credentials.
 *
 * | `type`        | One entry per                    | `key`     | `value`          | `group`                    |
 * | ------------- | -------------------------------- | --------- | ---------------- | -------------------------- |
 * | `own-devices` | untagged device of the requestor | node id   | name             |                            |
 * | `postures`    | `posture:p0_*` posture           | posture   | its assertions   | the attribute key it reads |
 *
 * `own-devices` leaves out devices another tailnet shares in.
 */
export const listerQuery = z.discriminatedUnion("type", [
  z.object({
    type: z.literal("own-devices"),
    context: tailnetCredentials,
    email,
  }),
  z.object({ type: z.literal("postures"), context: tailnetCredentials }),
]);

export type ListerQuery = z.infer<typeof listerQuery>;

/** What every lister returns: the framework's `SelectItem`s. */
export const listerResponse = z
  .object({
    key: z.string(),
    value: z.string(),
    group: z.string().optional(),
  })
  .array();

export type ListerResponse = z.infer<typeof listerResponse>;

/** A Tailscale node id, such as `nAbc123CNTRL`, which becomes a path segment. */
export const nodeId = z
  .string()
  .regex(/^[A-Za-z0-9]{1,64}$/, "must be a Tailscale node id");
