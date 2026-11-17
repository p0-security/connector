import { z } from "zod";

// copied from services/p0-connector-redshift-ai/src/context.ts
// Closed, so that a request can't send the connector's calls to an endpoint
// outside AWS's regional ones.
const region = z.string().regex(/^[a-z]{2}(-[a-z]+)+-\d{1,2}$/);

/** An EC2 instance id: `i-` and 8 or 17 hex digits. */
const instanceId = z.string().regex(/^i-(?:[0-9a-f]{8}|[0-9a-f]{17})$/);

/**
 * One install: the region whose SSM managed instances the connector reaches,
 * as its own execution role.
 */
export const installContext = z.object({ region });

export type InstallContext = z.infer<typeof installContext>;

/** The instance an agent reaches, and the region SSM manages it in. */
export const instance = z.object({ id: instanceId, region });

export type Instance = z.infer<typeof instance>;

/**
 * What every access request carries. `secrets` says where the connector
 * writes the key it mints. It names a vault, never a secret's value: the
 * connector reads nothing secret from its input.
 */
export const requestContext = z.object({
  requestId: z.string().min(1),
  secrets: z.object({ manager: z.literal("aws"), region }),
  instance,
});

export type RequestContext = z.infer<typeof requestContext>;
