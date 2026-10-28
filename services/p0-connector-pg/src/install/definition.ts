import { z } from "zod";

export const installValidation = z.object({
  canConnect: z.boolean(),
  grantedRoles: z.array(z.string()),
});
export type InstallValidation = z.infer<typeof installValidation>;
