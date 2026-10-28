import { newZodResourceRootParsers } from "@p0security/connector";
import { z } from "zod";

import { tailnetCredentials } from "../../credentials.ts";
import {
  P0_ATTRIBUTE_PREFIX,
  P0_POSTURE_PREFIX,
} from "../../tailscale/inventory.ts";
import {
  email,
  listerQuery,
  listerResponse,
  nodeId,
  requestId,
} from "../common/definition.ts";

/**
 * A P0 posture's name: lower-case letters, digits and `_`, short enough that
 * its attribute key fits Tailscale's 128 characters.
 */
const POSTURE_NAME = /^[a-z0-9_]{1,118}$/;

/**
 * The posture whose attribute install validation sets on a device for a
 * minute. A request naming it would get a grant the check also opens.
 */
export const INSTALL_CHECK_POSTURE = `${P0_POSTURE_PREFIX}install_check`;

/** A P0 posture, `posture:p0_<name>`, which the customer's policy file defines. */
export const postureName = z
  .string()
  .refine(
    (value) =>
      value.startsWith(P0_POSTURE_PREFIX) &&
      POSTURE_NAME.test(value.slice(P0_POSTURE_PREFIX.length)),
    "must be a P0 posture, such as posture:p0_prod_db"
  )
  .refine(
    (value) => value !== INSTALL_CHECK_POSTURE,
    // The app wraps a message that starts with "must" as "The target <message>."
    `must not be ${INSTALL_CHECK_POSTURE}, which P0's install check sets`
  );

/**
 * The device attribute a posture's assertion reads,
 * `custom:p0_<name> == true`. Derived on its own from the posture's name, so
 * a change to how postures are spelled leaves the keys alone.
 */
export const attributeKeyFor = (posture: string): string =>
  `${P0_ATTRIBUTE_PREFIX}${posture.slice(P0_POSTURE_PREFIX.length)}`;

/**
 * A device attribute key P0 sets: `attributeKeyFor` of a P0 posture. A key
 * such as `custom:p0_Prod` shares the prefix but is the customer's.
 */
export const p0AttributeKey = z
  .string()
  .regex(
    /^custom:p0_[a-z0-9_]{1,118}$/,
    "must be a P0 attribute key, such as custom:p0_db"
  );

/** The requestor and the device they chose. */
const userBody = z.object({ email, deviceId: nodeId });

/** The device is the user: two of one requestor's devices never share a key set. */
const userId = nodeId;

/**
 * One posture the device holds, until the latest end among the open
 * requests that carry it. A request with no end is refused.
 */
const policy = z.object({ posture: postureName, expiresAt: z.iso.datetime() });

/**
 * The tailnet's credentials, the request, whether it's a grant or a revoke,
 * and the requestor, whose device a grant must be.
 */
export const requestContext = tailnetCredentials.extend({
  requestId,
  operation: z.enum(["grant", "revoke"]),
  email,
});

export type PostureContext = z.infer<typeof requestContext>;

export const spec = newZodResourceRootParsers({
  userBody,
  userId,
  policy,
  listerQuery,
  listerResponse,
  requestContext,
});

/** A posture destination: a P0 posture the customer's policy file defines. */
export const destination = z.object({
  type: z.literal("posture"),
  target: postureName,
});

export type Destination = z.infer<typeof destination>;
