import type {
  Item,
  ItemOverview,
  ItemShareAccountPolicy,
  ValidRecipient,
  VaultOverview,
} from "@1password/sdk";
import { vi } from "vitest";

import type { OnePasswordClient } from "../client.ts";

// Named as the SDK names its own, which is how the connector tells them
// apart. Like the SDK's, they leave `name` as `Error`.
export class RateLimitExceededError extends Error {}
export class AuthExpiredError extends Error {}

/** An item overview, as `items.list` returns it. */
export const fakeItem = (id: string, title: string): ItemOverview =>
  ({
    id,
    title,
    category: "Login",
    vaultId: "",
    websites: [],
    tags: [],
    createdAt: new Date(0),
    updatedAt: new Date(0),
    state: "active",
  }) as unknown as ItemOverview;

/** A share link, with a marker a leak check can search for. */
export const LINK = "https://share.1password.com/s#SENTINEL-link-8e2f";

/** A field value on every full item, with a marker a leak check can search for. */
export const FIELD_VALUE = "SENTINEL-field-value-4b1d";

/** A policy that allows sharing with a person, by email, for up to 30 days. */
export const SHARING_POLICY = {
  maxExpiry: "ThirtyDays",
  defaultExpiry: "SevenDays",
  allowedTypes: ["Authenticated", "Public"],
  allowedRecipientTypes: ["Email", "Domain"],
  files: { allowed: true, maxSize: 0 },
} as unknown as ItemShareAccountPolicy;

export type FakeOnePasswordState = {
  /** The vaults the service account can see, by ID, with their titles. */
  vaults: Map<string, string>;
  /** Each vault's active items. */
  items: Map<string, ItemOverview[]>;
  policy: ItemShareAccountPolicy;
};

/**
 * A 1Password account as the SDK's client shows it to one service account.
 * A vault it can't see fails the call, as the SDK does, with a bare error.
 */
export const newFakeOnePassword = (state: FakeOnePasswordState) => {
  const requireVault = (vault: string) => {
    const title = state.vaults.get(vault);
    if (title === undefined) throw new Error(`no vault ${vault}`);
    return title;
  };
  const client = {
    vaults: {
      list: vi.fn(async () =>
        [...state.vaults].map(
          ([id, title]) => ({ id, title }) as unknown as VaultOverview
        )
      ),
      getOverview: vi.fn(async (vault: string) => {
        const title = requireVault(vault);
        return { id: vault, title } as unknown as VaultOverview;
      }),
    },
    items: {
      list: vi.fn(async (vault: string) => {
        requireVault(vault);
        return state.items.get(vault) ?? [];
      }),
      // The full item, field values and all, as the SDK returns it.
      get: vi.fn(async (vault: string, itemId: string) => {
        requireVault(vault);
        const overview = state.items
          .get(vault)
          ?.find(({ id }) => id === itemId);
        if (overview === undefined) throw new Error(`no item ${itemId}`);
        return {
          ...overview,
          fields: [{ id: "password", title: "password", value: FIELD_VALUE }],
          notes: FIELD_VALUE,
        } as unknown as Item;
      }),
      shares: {
        getAccountPolicy: vi.fn(async (vault: string, _itemId: string) => {
          requireVault(vault);
          return state.policy;
        }),
        validateRecipients: vi.fn(
          async (
            _policy: ItemShareAccountPolicy,
            recipients: string[]
          ): Promise<ValidRecipient[]> =>
            recipients.map((email) => ({
              type: "Email",
              parameters: { email },
            }))
        ),
        create: vi.fn(
          async (
            _item: Item,
            _policy: ItemShareAccountPolicy,
            _params: unknown
          ) => LINK
        ),
      },
    },
  };
  return {
    state,
    client,
    asClient: () => client as unknown as OnePasswordClient,
  };
};

export type FakeOnePassword = ReturnType<typeof newFakeOnePassword>;
