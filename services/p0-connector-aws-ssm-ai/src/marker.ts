import { createHash } from "node:crypto";

const MARKER_LENGTH = 32;

/**
 * The marker of a holder group: the grants that share one secret, and so one
 * key. The provisioning script takes 1 to 64 letters, digits, `_` or `-`. A
 * secret's name holds `/` and can be longer, so the marker is the start of
 * the name's SHA-256, in hex. The same name always gives the same marker.
 */
export const markerFor = (secretName: string) =>
  createHash("sha256").update(secretName).digest("hex").slice(0, MARKER_LENGTH);
