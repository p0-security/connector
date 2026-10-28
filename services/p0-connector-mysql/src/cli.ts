#!/usr/bin/env node
import { runConnectorCli } from "@p0security/connector-cli";
import type { TRPCClient } from "@trpc/client";
import { z } from "zod";

import { type MySqlConnectorRouter, MySqlConnectorSpec } from "./index.js";

void runConnectorCli({
  parsers: MySqlConnectorSpec.role,
  optionsSchema: z.object({
    dbHost: z.string().describe("The database host"),
    dbPort: z.number().default(3306).describe("The database port"),
    dbUser: z.string().describe("The database user"),
  }),
  selectClient: (client: TRPCClient<MySqlConnectorRouter>) =>
    client.mysql.accesses.role,
  toUserBody: (user) => user,
  toPolicy: (rolename) => ({ type: "role" as const, rolename }),
  newContext: (argv) => ({
    requestId: "",
    db: {
      p0User: argv.dbUser,
      host: argv.dbHost,
      port: argv.dbPort,
      cloud: "rds" as const,
    },
  }),
});
