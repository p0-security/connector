import type {
  ResourceHierarchyEndpoint,
  ResourceHierarchyParsers,
  ResourceHierarchyRouter,
  ResourceHierarchySchema,
} from "@p0security/connector";
import {
  newResourceHierarchyConnectorMethods,
  newTRPCConnectorClient,
} from "@p0security/connector";
import type { TRPCClient } from "@trpc/client";
import type { AnyRouter } from "@trpc/server";
import yargs from "yargs";
import { hideBin } from "yargs/helpers";
import { z } from "zod";

import { assertNever } from "./assertNever.js";
import { newCloudRunLink, newLambdaLink } from "./link.js";
import { yargsOptionsFromSchema } from "./yargsOptionsFromSchema.js";

export const transportArgsSchema = z.xor([
  z.object({
    endpoint: z
      .string()
      .describe(
        "The Cloud Run connector URL (mutually exclusive with --lambdaArn)"
      ),
  }),
  z.object({
    lambdaArn: z
      .string()
      .describe(
        "The AWS Lambda function ARN (mutually exclusive with --endpoint)"
      ),
  }),
]);

/** Narrows the full tRPC client to just the resource-hierarchy endpoints. */
type ScopedRoleClient<Schema extends ResourceHierarchySchema> = Pick<
  TRPCClient<ResourceHierarchyRouter<Schema>>,
  ResourceHierarchyEndpoint
>;

export type ConnectorCliConfig<
  Schema extends ResourceHierarchySchema,
  Router extends AnyRouter,
  OptionsSchema extends z.ZodObject<any>,
> = {
  /** Drives the types & parsing for the payloads to/from the connector. */
  parsers: ResourceHierarchyParsers<Schema>;
  /** Service-specific options. */
  optionsSchema: OptionsSchema;
  /** Selects the trpc subrouter for the access-role methods. */
  selectClient: (client: TRPCClient<Router>) => ScopedRoleClient<Schema>;
  /** Builds the per-request context from the parsed CLI args. */
  newContext: (
    argv: z.output<OptionsSchema> & z.output<typeof transportArgsSchema>
  ) => Schema["RequestContext"];
  /**
   * Builds the schema's user body from a `<user>` argument. It's sent on
   * `provisionUser`, `bindAccessResource` and `unbindAccessResource`.
   */
  toUserBody: (user: string) => Schema["UserBody"];
  /** Builds a single policy from a `--role` value. */
  toPolicy: (rolename: string) => Schema["Policy"];
};

/**
 * Builds and runs the connector management CLI shared by every database
 * connector. The CLI talks to the connector over tRPC, choosing its transport
 * (Cloud Run HTTP or AWS Lambda) from mutually exclusive `--endpoint` /
 * `--lambdaArn` flags. All commands are defined here; callers supply the
 * service-specific spec, options schema, router namespace, and request context.
 */
export const runConnectorCli = <
  Schema extends ResourceHierarchySchema,
  Router extends AnyRouter,
  OptionsSchema extends z.ZodObject<any>,
>(
  config: ConnectorCliConfig<Schema, Router, OptionsSchema>
) => {
  const newClient = (args: z.output<typeof transportArgsSchema>) => {
    const link =
      "endpoint" in args
        ? newCloudRunLink(args.endpoint)
        : "lambdaArn" in args
          ? newLambdaLink(args.lambdaArn)
          : assertNever(args);

    return newResourceHierarchyConnectorMethods(
      config.parsers,
      config.selectClient(newTRPCConnectorClient<Router>({ links: [link] }))
    );
  };

  const baseSchema = transportArgsSchema.and(config.optionsSchema);
  const userArgsSchema = baseSchema.and(z.object({ user: z.string() }));
  const resourceArgsSchema = baseSchema.and(z.object({ resource: z.string() }));
  const resourceRoleArgsSchema = baseSchema.and(
    z.object({ resource: z.string(), role: z.array(z.string()) })
  );
  const userResourceArgsSchema = baseSchema.and(
    z.object({ user: z.string(), resource: z.string() })
  );
  const userResourceRoleArgsSchema = baseSchema.and(
    z.object({
      user: z.string(),
      resource: z.string(),
      role: z.array(z.string()),
    })
  );

  return yargs(hideBin(process.argv))
    .env("P0")
    .options(yargsOptionsFromSchema(baseSchema))
    .command(
      "provisionUser <user>",
      "Create a user in the resource hierarchy",
      (yargs) =>
        yargs.positional("user", {
          describe: "The user to provision",
          type: "string",
          demandOption: true,
        }),
      async (raw) => {
        const argv = userArgsSchema.parse(raw);
        await newClient(argv).provisionUser({
          userBody: config.toUserBody(argv.user),
          context: config.newContext(argv),
        });
      }
    )
    .command(
      "createAccessResource <resource>",
      "Create an access resource in the resource hierarchy",
      (yargs) =>
        yargs.positional("resource", {
          describe: "The access resource to create",
          type: "string",
          demandOption: true,
        }),
      async (raw) => {
        const argv = resourceArgsSchema.parse(raw);
        await newClient(argv).createAccessResource({
          resourceBody: argv.resource,
          context: config.newContext(argv),
        });
      }
    )
    .command(
      "addPoliciesToResource <resource> <policy>",
      "Add a policy to an access resource in the resource hierarchy",
      (yargs) =>
        yargs
          .positional("resource", {
            describe: "The access resource to add the policy to",
            type: "string",
            demandOption: true,
          })
          .option("role", {
            describe: "A role to add to the access resource",
            type: "string",
            demandOption: true,
            array: true,
          }),
      async (raw) => {
        const argv = resourceRoleArgsSchema.parse(raw);
        await newClient(argv).addPoliciesToResource({
          resourceId: argv.resource,
          policies: argv.role.map(config.toPolicy),
          context: config.newContext(argv),
        });
      }
    )
    .command(
      "bindAccessResource <user> <resource>",
      "Bind an access resource to a user in the resource hierarchy",
      (yargs) =>
        yargs
          .positional("user", {
            describe: "The user to bind the resource to",
            type: "string",
            demandOption: true,
          })
          .positional("resource", {
            describe: "The access resource to bind",
            type: "string",
            demandOption: true,
          }),
      async (raw) => {
        const argv = userResourceArgsSchema.parse(raw);
        await newClient(argv).bindAccessResource({
          userId: argv.user,
          userBody: config.toUserBody(argv.user),
          resourceId: argv.resource,
          context: config.newContext(argv),
        });
      }
    )
    .command(
      "up <user> <resource>",
      "Provision a user, create a resource, attach roles, and bind them",
      (yargs) =>
        yargs
          .positional("user", {
            describe: "The user to bind the resource to",
            type: "string",
            demandOption: true,
          })
          .positional("resource", {
            describe: "The access resource to bind",
            type: "string",
            demandOption: true,
          })
          .option("role", {
            describe: "A role to add to the access resource",
            type: "string",
            demandOption: true,
            array: true,
          }),
      async (raw) => {
        const argv = userResourceRoleArgsSchema.parse(raw);
        const client = newClient(argv);
        const context = config.newContext(argv);

        await client.provisionUser({
          userBody: config.toUserBody(argv.user),
          context,
        });
        await client.createAccessResource({
          resourceBody: argv.resource,
          context,
        });
        await client.addPoliciesToResource({
          resourceId: argv.resource,
          policies: argv.role.map(config.toPolicy),
          context,
        });
        await client.bindAccessResource({
          userId: argv.user,
          userBody: config.toUserBody(argv.user),
          resourceId: argv.resource,
          context,
        });
      }
    )
    .command(
      "down <user> <resource>",
      "Unbind a resource from a user, detach roles, and delete the resource",
      (yargs) =>
        yargs
          .positional("user", {
            describe: "The user to unbind the resource from",
            type: "string",
            demandOption: true,
          })
          .positional("resource", {
            describe: "The access resource to unbind",
            type: "string",
            demandOption: true,
          })
          .option("role", {
            describe: "A role to add to the access resource",
            type: "string",
            demandOption: true,
            array: true,
          }),
      async (raw) => {
        const argv = userResourceRoleArgsSchema.parse(raw);
        const client = newClient(argv);
        const context = config.newContext(argv);

        await client.unbindAccessResource({
          userId: argv.user,
          userBody: config.toUserBody(argv.user),
          resourceId: argv.resource,
          context,
        });
        await client.removePoliciesFromResource({
          resourceId: argv.resource,
          policies: argv.role.map(config.toPolicy),
          context,
        });
        await client.deleteAccessResource({
          resourceId: argv.resource,
          context,
        });
      }
    )
    .strictCommands()
    .demandCommand()
    .parse();
};
