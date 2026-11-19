import type { AnyConnectorTRPCInstance } from "@p0security/connector-core";

import { installContext } from "../context.ts";
import { newNotImplementedError } from "../not-implemented.ts";
import type { InstallValidation } from "./definition.ts";

/**
 * Lets the installer confirm the connector can manage a target. `get` is to
 * run the checks of `PG_VAULTED_INSTALL_STEPS` in order and write nothing.
 *
 * Not implemented: it parses its input, then throws
 * {@link newNotImplementedError}.
 */
export const router = (t: AnyConnectorTRPCInstance) => {
  const { router, procedure } = t;

  return router({
    get: procedure
      .input(installContext.parse)
      .query(async (): Promise<InstallValidation> => {
        throw newNotImplementedError("install.validation.get");
      }),
  });
};
