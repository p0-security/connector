import { z } from "zod";

import { destination } from "../accesses/posture/definition.ts";
import { tailnetCredentials } from "../credentials.ts";

// What a request names: a P0 posture the customer's policy file defines.
export {
  type Destination,
  destination,
} from "../accesses/posture/definition.ts";

export const destinationCheckInput = z.object({
  context: tailnetCredentials,
  destination,
});

export type DestinationCheckInput = z.infer<typeof destinationCheckInput>;

/**
 * A customer grant a posture gates, as P0 found it in the policy file, for
 * the approver. Customer values, so only their shape is checked. A legacy
 * `acls` entry comes in the same shape: its hosts as `dst`, their ports
 * (after its `proto`) as `ip`.
 */
export const unlockedGrant = z.object({
  /** Who the grant is for: the posture opens it only to a requestor it names. */
  src: z.array(z.string()),
  dst: z.array(z.string()),
  ip: z.array(z.string()).optional(),
  via: z.array(z.string()).optional(),
  /** The capabilities the grant gives, each with its values as the file has them. */
  app: z.record(z.string(), z.array(z.unknown())).optional(),
  /**
   * The posture that gates the entry: the requested one, or another posture
   * whose assertions read the attribute P0 sets for it.
   */
  posture: z.string(),
  /**
   * True when the entry's own `srcPosture` names no posture (missing, `null`
   * or `[]`) and `posture` gates it through the policy file's
   * `defaultSrcPosture`.
   */
  fromDefault: z.boolean().optional(),
  /**
   * The other postures in the entry's posture list that don't read the
   * attribute. A device passing any one of them reaches the entry without
   * P0. Absent when there are none.
   */
  alsoOpenedBy: z.array(z.string()).optional(),
});

export type UnlockedGrant = z.infer<typeof unlockedGrant>;

/** A customer `ssh` rule a posture gates, for the approver. */
export const unlockedSshRule = z.object({
  /** Who the rule is for: the posture opens it only to a requestor it names. */
  src: z.array(z.string()),
  dst: z.array(z.string()),
  /** The SSH users the rule lets the requestor log in as. */
  users: z.array(z.string()),
  /** `accept`, or `check` when the requestor must authenticate again. */
  action: z.string().optional(),
  /** As {@link unlockedGrant}'s. */
  posture: z.string(),
  /** As {@link unlockedGrant}'s. */
  fromDefault: z.boolean().optional(),
  /** As {@link unlockedGrant}'s. */
  alsoOpenedBy: z.array(z.string()).optional(),
});

export type UnlockedSshRule = z.infer<typeof unlockedSshRule>;

/** What a posture unlocks: the customer's `grants` and `ssh` entries. */
export const unlocks = z.object({
  /** The `grants` entries, then the legacy `acls` entries, each in file order. */
  grants: z.array(unlockedGrant),
  ssh: z.array(unlockedSshRule),
});

export type Unlocks = z.infer<typeof unlocks>;

/**
 * What `install.destination.check` answers for a posture the policy file
 * defines: the attribute key its assertion reads, and the grants it
 * unlocks.
 */
export const destinationCheck = z.object({
  kind: z.literal("posture"),
  posture: z.string(),
  attribute: z.string(),
  /** The posture's assertions, as the policy file has them. */
  assertions: z.array(z.string()),
  /**
   * The `grants`, `acls` and `ssh` entries that the posture, or another
   * posture reading its attribute, gates by their own `srcPosture` or the
   * file's `defaultSrcPosture`. Both lists are empty when they gate none.
   */
  unlocks,
});

export type DestinationCheck = z.infer<typeof destinationCheck>;
