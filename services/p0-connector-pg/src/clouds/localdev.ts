import type { CloudConfig } from "./index.ts";

export const localConfig: CloudConfig = {
  fetchDbPassword: async () => "psqlpass",
  poolConfig: async () => ({}),
  sslConfig: async () => false,
};
