import { newZodResourceRootParsers } from "@p0security/connector-core";
import { z } from "zod";

import { installContext, requestContext } from "../../context.ts";
import { RUN_AS_PATTERN, USER_PATTERN } from "../../script/provision.ts";

/**
 * The user a session switches to with sudo, `root` or another Linux user.
 * Blank runs as the agent's own Linux user.
 */
const runAs = z.union([z.literal(""), z.string().regex(RUN_AS_PATTERN)]);

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
  /**
   * The user the group's key line switches to. P0 gives each run-as user a
   * secret of its own, so a group has one.
   */
  runAs: runAs.optional(),
});

/** The secret's ARN. */
const userId = z.string().min(1);

/**
 * What P0 granted one holder of the group. `sudo` comes only from a grant
 * made before run-as, and `true` counts as run-as `root`.
 */
const policy = z.object({
  runAs: runAs.optional(),
  sudo: z.boolean().optional(),
});

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
