import type { CloudConfig } from "./index.ts";

export const localConfig: CloudConfig = {
  // The superuser of the local server the database tests run against.
  fetchCredential: async () => ({
    username: "pspladmin",
    password: "psqlpass",
  }),
  poolConfig: async () => ({}),
  sslConfig: async () => false,
};
