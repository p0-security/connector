import { describe, expect, it } from "vitest";

import {
  AWS_SECRET,
  CREDENTIALS,
  GCP_SECRET,
  ITEM,
} from "../../../__tests__/fixtures.ts";
import { spec } from "../definition.ts";

describe("listerQuery", () => {
  // Listing the vaults needs only the account's token, no vault.
  it("parses a vaults query carrying only the token's pointer", () => {
    const context = { tokenSecret: AWS_SECRET };

    expect(spec.listerQuery({ context, type: "vaults" })).toEqual({
      context,
      type: "vaults",
    });
  });

  it.each([{ type: "items" }, { type: "sharing-policy", itemId: ITEM }])(
    "parses a $type query carrying the credentials as its context",
    (query) => {
      expect(spec.listerQuery({ context: CREDENTIALS, ...query })).toEqual({
        context: CREDENTIALS,
        ...query,
      });
    }
  );

  it("rejects credentials beside the context instead of in it", () => {
    expect(() => spec.listerQuery({ ...CREDENTIALS, type: "items" })).toThrow();
  });

  it("rejects a sharing-policy query without an item", () => {
    expect(() =>
      spec.listerQuery({ context: CREDENTIALS, type: "sharing-policy" })
    ).toThrow();
  });

  it.each([
    "0ab70deb-065a-43fc-acd5-5d48caa945d8",
    "YDAHJNLXHOGQZMKOGDBR5YO2NU",
    "",
  ])("rejects %j as an item ID", (itemId) => {
    expect(() =>
      spec.listerQuery({
        context: CREDENTIALS,
        type: "sharing-policy",
        itemId,
      })
    ).toThrow();
  });

  it("rejects a malformed vault ID", () => {
    expect(() =>
      spec.listerQuery({
        context: { ...CREDENTIALS, vault: "engineering" },
        type: "items",
      })
    ).toThrow();
  });

  // Share creation is the connector's own route, never a listing.
  it.each(["create-share", "share", "item"])(
    "rejects the unknown type %s",
    (type) => {
      expect(() => spec.listerQuery({ context: CREDENTIALS, type })).toThrow();
    }
  );
});

describe("listerResponse", () => {
  it("keeps only the key, the value and the group", () => {
    expect(
      spec.listerResponse([
        { key: ITEM, value: "Prod database", group: "Login", password: "x" },
      ])
    ).toEqual([{ key: ITEM, value: "Prod database", group: "Login" }]);
  });
});

describe("IDs", () => {
  const listing = (vault: string) => () =>
    spec.listerQuery({ context: { ...CREDENTIALS, vault }, type: "items" });

  // The whole value must be an ID: anything around one is refused.
  it.each([
    ["with a prefix", `x${CREDENTIALS.vault}`],
    ["with a suffix", `${CREDENTIALS.vault}/`],
    ["a character long", `${CREDENTIALS.vault}a`],
    ["a character short", CREDENTIALS.vault.slice(1)],
  ])("refuses a vault ID %s", (_case, vault) => {
    expect(listing(vault)).toThrow("must be a 1Password vault ID");
  });

  it.each([
    ["with a prefix", `x${ITEM}`],
    ["with a suffix", `${ITEM}/`],
  ])("refuses an item ID %s", (_case, itemId) => {
    expect(() =>
      spec.listerQuery({
        context: CREDENTIALS,
        type: "sharing-policy",
        itemId,
      })
    ).toThrow("must be a 1Password item ID");
  });
});

describe("tokenSecret", () => {
  const withSecret = (tokenSecret: unknown) =>
    spec.listerQuery({
      context: { ...CREDENTIALS, tokenSecret },
      type: "items",
    });

  it.each([AWS_SECRET, GCP_SECRET])("takes a $manager pointer", (secret) => {
    expect(withSecret(secret)).toMatchObject({
      context: { tokenSecret: secret },
    });
  });

  it.each([
    ["an AWS secret ID", { ...AWS_SECRET, secretId: "" }],
    ["an AWS region", { ...AWS_SECRET, region: "" }],
    ["a Google secret ID", { ...GCP_SECRET, secretId: "" }],
    ["a Google project", { ...GCP_SECRET, projectId: "" }],
  ])("refuses an empty %s", (_case, secret) => {
    expect(() => withSecret(secret)).toThrow();
  });
});

describe("requestContext", () => {
  it("carries the request's ID beside the credentials", () => {
    expect(spec.requestContext({ ...CREDENTIALS, requestId: "req-1" })).toEqual(
      { ...CREDENTIALS, requestId: "req-1" }
    );
  });

  it("refuses a context without the request's ID", () => {
    expect(() => spec.requestContext(CREDENTIALS)).toThrow();
  });
});
