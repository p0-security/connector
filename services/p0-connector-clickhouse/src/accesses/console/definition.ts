import { newZodResourceHierarchyParsers } from "@p0security/connector-core";
import { z } from "zod";

import { accessSchemas } from "../common/definition.ts";

/**
 * The console roles a `console` request picks from:
 *
 * - `sql-console-readonly` and `sql-console-admin`: SQL console on the
 *   service, read-only or as admin, through the policy's `tags.roleV2`.
 * - `service-reader` and `service-admin`: the service permissions of
 *   ClickHouse Cloud's system role Service Reader or Service Admin, copied
 *   onto the service at grant time.
 */
export const CONSOLE_ROLES = [
  "sql-console-readonly",
  "sql-console-admin",
  "service-reader",
  "service-admin",
] as const;

export type ConsoleRole = (typeof CONSOLE_ROLES)[number];

export const policy = z
  .object({
    type: z.literal("console"),
    consoleRole: z.enum(CONSOLE_ROLES).meta({
      description: `The console role: ${CONSOLE_ROLES.join(", ")}`,
    }),
  })
  .meta({
    description:
      "SQL console through tags.roleV2, or a system role's service permissions, on the one service",
  });

export type ConsolePolicy = z.infer<typeof policy>;

export const spec = newZodResourceHierarchyParsers({
  ...accessSchemas,
  policy,
});
