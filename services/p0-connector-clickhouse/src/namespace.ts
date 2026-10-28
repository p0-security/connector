import { refusal } from "./refusals.ts";

/**
 * The prefix of every name the connector owns in ClickHouse Cloud: its
 * custom roles and its Query API endpoints. The connector never changes or
 * deletes a role or an endpoint whose name doesn't start with it.
 */
export const P0_PREFIX = "p0_";

/** Whether a role or endpoint name is one the connector may change or delete. */
export const isP0Name = (name: string): boolean => name.startsWith(P0_PREFIX);

/**
 * Refuses, as `not_p0_role`, a role the connector may not create, change or
 * delete: one whose name doesn't start with {@link P0_PREFIX}.
 */
export const requireP0Role = (name: string): void => {
  if (!isP0Name(name)) {
    throw refusal({
      reason: "not_p0_role",
      message: `P0 only changes the ClickHouse Cloud roles it created, whose names start with ${P0_PREFIX}, and ${name} isn't one.`,
      payload: { role: name },
    });
  }
};
