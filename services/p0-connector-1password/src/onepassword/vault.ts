import type {
  ItemListFilter,
  ItemOverview,
  ItemShareAccountPolicy,
} from "@1password/sdk";

import type { OnePasswordClient } from "../client.ts";

const ACTIVE_ITEMS: ItemListFilter = {
  type: "ByState",
  content: { active: true, archived: false },
};

/** What the connector reads from one vault, over the SDK's client. */
export type VaultReader = {
  /** The vault's name. */
  title: () => Promise<string>;
  /** The vault's active items, without their fields. */
  listItems: () => Promise<ItemOverview[]>;
  /** The account's sharing policy, which 1Password reads through an item. */
  sharingPolicy: (itemId: string) => Promise<ItemShareAccountPolicy>;
};

export const newVaultReader = (
  client: OnePasswordClient,
  vault: string
): VaultReader => ({
  title: async () => (await client.vaults.getOverview(vault)).title,
  listItems: () => client.items.list(vault, ACTIVE_ITEMS),
  sharingPolicy: (itemId) =>
    client.items.shares.getAccountPolicy(vault, itemId),
});

/** The vaults the service account can see, by ID and title. */
export const listVaults = async (client: OnePasswordClient) =>
  (await client.vaults.list()).map(({ id, title }) => ({ id, title }));
