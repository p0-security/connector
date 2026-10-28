import { newZodResourceRootParsers } from "@p0security/connector";
import { z } from "zod";

import {
  accountId,
  projectId,
  secretId,
  secretRef,
  site,
} from "../../install/definition.ts";
import { listerQuery, listerResponse } from "../lister.ts";

/**
 * The "user" of this access is the request's own token secret, by its bare
 * name in the vault project. The connector creates it on grant and deletes it
 * on revoke. No other request reads or deletes it.
 */
export const userBody = secretId;
export const userId = secretId;

/** The pool account P0 leased to the request. */
const policy = z.object({ accountId });

/**
 * `vault.projectId` is the project the token secret is created in.
 * `poolSecret` holds the leased pool account's API key, as the secret's whole
 * value.
 */
const requestContext = z.object({
  requestId: z.string(),
  site,
  vault: z.object({ projectId }),
  poolSecret: secretRef,
});

export const schema = {
  userBody,
  userId,
  policy,
  listerQuery,
  listerResponse,
  requestContext,
};

export const spec = newZodResourceRootParsers(schema);
