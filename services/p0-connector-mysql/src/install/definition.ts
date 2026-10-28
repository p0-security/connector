import { z } from "zod";

export const installValidation = z.object({
  canConnect: z.boolean(),
  schemaPrivileges: z.array(
    z.object({
      PRIVILEGE_TYPE: z.string(),
      TABLE_SCHEMA: z.string(),
      IS_GRANTABLE: z.boolean(),
    })
  ),
  globalPrivileges: z.array(
    z.object({ PRIVILEGE_TYPE: z.string(), IS_GRANTABLE: z.boolean() })
  ),
});
export type InstallValidation = z.infer<typeof installValidation>;
