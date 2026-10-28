#!/usr/bin/env -S node --conditions=@p0security/development
import { runConnectorCli } from "@p0security/connector-cli";
import type { TRPCClient } from "@trpc/client";
import { z } from "zod";

import type { PostgresConnectorRouter } from "./index.js";
import { PostgresConnectorSpec } from "./index.js";

void runConnectorCli({
  parsers: PostgresConnectorSpec.role,
  optionsSchema: z.object({
    dbHost: z.string().describe("The database host"),
    dbPort: z.number().default(5432).describe("The database port"),
    dbUser: z.string().default("p0_iam_manager").describe("The database user"),
    dbName: z.string().default("postgres").describe("The database name"),
  }),
  selectClient: (client: TRPCClient<PostgresConnectorRouter>) =>
    client.pg.accesses.role,
  toUserBody: (user) => user,
  toPolicy: (rolename) => ({ type: "role" as const, rolename }),
  newContext: (argv) => ({
    requestId: "",
    db: {
      p0User: argv.dbUser,
      host: argv.dbHost,
      port: argv.dbPort,
      database: argv.dbName,
      cloud: "rds" as const,
    },
  }),
});
