import { z } from "zod";

// Neither access lists anything: P0 looks up accounts and projects through
// install.
export const listerQuery = z.object({ type: z.literal("unsupported") });

export const listerResponse = z
  .object({ key: z.string(), value: z.string(), group: z.string().optional() })
  .array();
