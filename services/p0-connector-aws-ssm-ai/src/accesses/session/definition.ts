import { newZodResourceRootParsers } from "@p0security/connector-core";
import { z } from "zod";

import { installContext, requestContext } from "../../context.ts";
import { USER_PATTERN } from "../../script/provision.ts";

/**
 * A holder group: the grants that share one key to one instance, as one
 * Linux user. The "user" of this access is the secret that holds the key,
 * as it is for `p0-connector-github-ai`. P0 chooses both names.
 */
const userBody = z.object({
  /** The agent's Linux user on the instance. */
  user: z.string().regex(USER_PATTERN),
  /** The secret's name, within Secrets Manager's own rule for a name. */
  secretName: z.string().regex(/^[A-Za-z0-9/_+=.@-]{1,512}$/),
});

/** The secret's ARN. */
const userId = z.string().min(1);

/** What P0 granted one holder of the group. */
const policy = z.object({ sudo: z.boolean() });

const listerQuery = z.object({
  type: z.literal("instance"),
  context: installContext,
});

export type ListerQuery = z.infer<typeof listerQuery>;

const listerResponse = z
  .object({
    key: z.string(),
    value: z.string(),
    group: z.string().optional(),
  })
  .array();

export type ListerResponse = z.infer<typeof listerResponse>;

export const schema = {
  userBody,
  userId,
  policy,
  listerQuery,
  listerResponse,
  requestContext,
};

export const spec = newZodResourceRootParsers(schema);

/**
 * What the connector writes as the secret's value, as JSON. The gateway
 * reads it to open the session.
 */
export type SessionSecret = {
  /** The private key in OpenSSH's own format, for `ssh -i`. */
  privateKey: string;
  /** The Linux user to log in as. */
  user: string;
  /** The instance's SSH host public keys, each as `<type> <key>`. */
  hostKeys: string[];
};
