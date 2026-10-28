import {
  type AnyConnectorTRPCInstance,
  type ConnectorContext,
  type Logger,
  type ResourceRootConnectorPrimitives,
  type ResourceRootSchemaOf,
  newResourceRootRouter,
  throwAssertNever,
} from "@p0security/connector-core";

import { newOnePasswordClient } from "../../client.ts";
import { toConnectorError } from "../../onepassword/errors.ts";
import {
  type VaultReader,
  listVaults,
  newVaultReader,
} from "../../onepassword/vault.ts";
import {
  type AccountCredentials,
  type VaultCredentials,
  spec,
} from "./definition.ts";

type ResourceSchema = ResourceRootSchemaOf<typeof spec>;

/** Signs in with the account's token, and reads one of its vaults through it. */
export type ConnectVault = (
  credentials: VaultCredentials
) => Promise<VaultReader>;

const connectVault: ConnectVault = async ({ vault, tokenSecret }) =>
  newVaultReader(await newOnePasswordClient(tokenSecret), vault);

/** Signs in with the account's token, and lists the vaults it can see. */
export type ListAccountVaults = (
  credentials: AccountCredentials
) => Promise<{ id: string; title: string }[]>;

const listAccountVaults: ListAccountVaults = async ({ tokenSecret }) =>
  listVaults(await newOnePasswordClient(tokenSecret));

/**
 * The 1Password `share` access: a read-only share link to one item, for the
 * requestor's email only.
 *
 * P0 makes the link at stage, through the connector's own share route, so
 * the user primitives here change nothing in 1Password. The link expires on
 * 1Password's side, and P0 can't take it back early.
 */
export const newSharePrimitives = (
  logger: Logger,
  connect: ConnectVault = connectVault,
  listAccount: ListAccountVaults = listAccountVaults
): ResourceRootConnectorPrimitives<ResourceSchema> => ({
  // The perimeter's own check can't tell a grant from a revoke, and `list`
  // never runs it.
  validation: () => ({ user: null }),

  // Never `null`, and nothing is looked up: a share goes to an email, not
  // to a 1Password account.
  getUser: async (_context, email) => email,

  // Never reached, since `getUser` never returns `null`.
  createUser: async (_context, email) => email,

  // A deliberate no-op: there's no account to remove.
  deleteUser: async () => {},

  // A deliberate no-op. The share was made at stage, and 1Password has no
  // call that takes one back.
  setPoliciesForUser: async () => {},

  // No query is for one person, so none runs the allowed-domain check.
  // Vault and item titles can be sensitive, so only counts are logged.
  list: async (query) => {
    if (query.type === "vaults") {
      try {
        const vaults = await listAccount(query.context);
        logger.info({ count: vaults.length }, "listed the account's vaults");
        return vaults.map(({ id, title }) => ({ key: id, value: title }));
      } catch (error) {
        throw toConnectorError(error);
      }
    }
    const { vault } = query.context;
    const log = logger.child({ vault, type: query.type });
    try {
      const reader = await connect(query.context);
      switch (query.type) {
        case "items": {
          const items = await reader.listItems();
          log.info({ count: items.length }, "listed the vault's items");
          // Only these three: `ItemOverview` has no field values, and
          // nothing else it carries is P0's business.
          return items.map(({ id, title, category }) => ({
            key: id,
            value: title,
            group: category,
          }));
        }
        case "sharing-policy": {
          const policy = await reader.sharingPolicy(query.itemId);
          return [
            { key: "maxExpiry", value: policy.maxExpiry },
            { key: "defaultExpiry", value: policy.defaultExpiry },
            {
              key: "allowedRecipientTypes",
              value: policy.allowedRecipientTypes.join(","),
            },
            { key: "allowedTypes", value: policy.allowedTypes.join(",") },
          ];
        }
        default:
          throw throwAssertNever(query);
      }
    } catch (error) {
      throw toConnectorError(error, { vault });
    }
  },
});

export const router = (t: AnyConnectorTRPCInstance) =>
  newResourceRootRouter<ResourceSchema>(t, spec, (ctx: ConnectorContext) =>
    newSharePrimitives(ctx.logger)
  );
