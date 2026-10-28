import type { Logger } from "@p0security/connector-core";

import { isAlreadyAssigned, isNotFound } from "../../auth0/errors.ts";

/**
 * Runs a write, taking "already there" as done once a read confirms it.
 * Auth0 answers 409 for more than that: a member at the 50-role cap gets one
 * too.
 *
 * @returns whether this call wrote it, rather than finding it there
 */
export const adding = async (
  log: Logger,
  what: string,
  write: () => Promise<void>,
  isThere: () => Promise<boolean>
): Promise<boolean> => {
  try {
    await write();
    log.info(`added the ${what}`);
    return true;
  } catch (error) {
    if (!isAlreadyAssigned(error) || !(await isThere())) throw error;
    log.info(`the ${what} was already there`);
    return false;
  }
};

/**
 * Runs a removal, and takes a 404 as done: what it removes is already gone.
 *
 * @returns whether this call removed it, rather than finding it gone
 */
export const removing = async (
  log: Logger,
  what: string,
  write: () => Promise<void>
): Promise<boolean> => {
  try {
    await write();
    log.info(`removed the ${what}`);
    return true;
  } catch (error) {
    if (!isNotFound(error)) throw error;
    log.info(`the ${what} was already gone`);
    return false;
  }
};
