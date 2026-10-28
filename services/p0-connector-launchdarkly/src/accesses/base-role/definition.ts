import { newZodResourceRootParsers } from "@p0security/connector";
import { z } from "zod";

import { BASE_ROLES_BY_RANK } from "../../launchdarkly/roles.ts";
import {
  baseRequestContext,
  listerQuery,
  listerResponse,
  userBody,
  userId,
} from "../common/definition.ts";

/**
 * The base roles P0 grants, weakest first. LaunchDarkly ranks base roles
 * `no_access < reader < writer < admin < owner`. P0 never grants or writes
 * `owner`.
 */
export const baseRole = z
  .enum(BASE_ROLES_BY_RANK)
  .exclude(["no_access", "owner"]);

export type BaseRole = z.infer<typeof baseRole>;

/**
 * The base role the member held before P0 granted, which a revoke restores
 * when no sibling request still holds a role. `no_access` is one.
 */
export const priorBaseRole = z.enum(BASE_ROLES_BY_RANK).exclude(["owner"]);

export type PriorBaseRole = z.infer<typeof priorBaseRole>;

/**
 * A base role this request or a sibling holds. A grant raises the member to
 * the request's own role, and only raises. A revoke lowers the member to the
 * highest that remains, or to `priorRole` when none does, and only lowers.
 */
const policy = baseRole;

/**
 * `role` is the base role this request grants. `priorRole` is required: a
 * context that lost it must fail to parse, not read as "held none" and
 * lower the member to `no_access`.
 */
const requestContext = baseRequestContext.extend({
  priorRole: priorBaseRole,
  role: baseRole,
});

export const schema = {
  listerQuery,
  listerResponse,
  policy,
  requestContext,
  userBody,
  userId,
};

export const spec = newZodResourceRootParsers(schema);
