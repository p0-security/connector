import { createPrivateKey, createPublicKey, sign, verify } from "node:crypto";
import { describe, expect, it } from "vitest";

import { newKeyPair, toOpenSshKeyPair } from "../keys.ts";
import { PUBLIC_KEY_PATTERN } from "../script/provision.ts";
import { parseOpenSshPrivateKey, publicKeyOf } from "./openssh.ts";

// RFC 8032, section 7.1, test 1: a published seed and its public key.
const SEED = Buffer.from(
  "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
  "hex"
);
const PUBLIC = Buffer.from(
  "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
  "hex"
);
// `ssh-keygen -y` printed this for the private key below, on OpenSSH 7.4,
// 9.2, 9.6, 9.9 and 10.3.
const PUBLIC_LINE =
  "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINdamAGCsQq31Uv+08lkBzoO4XLz2qYjJa8CGmj3B1Ea";
const CHECK = Buffer.from("01020304", "hex");

describe("toOpenSshKeyPair", () => {
  const pair = toOpenSshKeyPair(SEED, PUBLIC, CHECK);
  const parsed = parseOpenSshPrivateKey(pair.privateKey);

  it("writes the public key as one line with no comment", () => {
    expect(pair.publicKey).toBe(PUBLIC_LINE);
    expect(PUBLIC_KEY_PATTERN.test(pair.publicKey)).toBe(true);
  });

  it("wraps the private key in OpenSSH's own armor, 70 characters a line", () => {
    const { lines } = parsed;
    expect(lines[0]).toBe("-----BEGIN OPENSSH PRIVATE KEY-----");
    expect(lines.at(-2)).toBe("-----END OPENSSH PRIVATE KEY-----");
    expect(lines.at(-1)).toBe("");
    const body = lines.slice(1, -2);
    expect(body.slice(0, -1).every((line) => line.length === 70)).toBe(true);
    expect(body.at(-1)?.length).toBeLessThanOrEqual(70);
    expect(body.join("")).toMatch(/^[A-Za-z0-9+/]+={0,2}$/);
  });

  it("writes an unencrypted openssh-key-v1 file with one key", () => {
    expect(parsed.magic).toBe("openssh-key-v1\0");
    expect(parsed.cipher).toBe("none");
    expect(parsed.kdf).toBe("none");
    expect(parsed.kdfOptions).toHaveLength(0);
    expect(parsed.nKeys).toBe(1);
    expect(parsed.trailing).toHaveLength(0);
  });

  it("writes the public key in both sections", () => {
    expect(parsed.publicBlob.toString("base64")).toBe(
      PUBLIC_LINE.split(" ")[1]
    );
    expect(parsed.keyType).toBe("ssh-ed25519");
    expect(parsed.publicKey.equals(PUBLIC)).toBe(true);
    expect(publicKeyOf(pair.privateKey)).toBe(PUBLIC_LINE);
  });

  it("writes the seed and then the public key as the private key", () => {
    expect(parsed.privateKey.equals(Buffer.concat([SEED, PUBLIC]))).toBe(true);
  });

  it("writes the check number twice, no comment, and pads to 8 bytes", () => {
    expect(parsed.check).toEqual([0x01020304, 0x01020304]);
    expect(parsed.comment).toBe("");
    expect(parsed.padding).toEqual([1, 2, 3, 4, 5]);
    expect(parsed.privateSection.length % 8).toBe(0);
  });
});

describe("newKeyPair", () => {
  it("mints a pair whose halves belong together", () => {
    const pair = newKeyPair();
    expect(PUBLIC_KEY_PATTERN.test(pair.publicKey)).toBe(true);
    expect(publicKeyOf(pair.privateKey)).toBe(pair.publicKey);

    const { privateKey, publicKey } = parseOpenSshPrivateKey(pair.privateKey);
    const seed = privateKey.subarray(0, 32);
    expect(privateKey.subarray(32).equals(publicKey)).toBe(true);
    // Node derives the public key from the seed alone, given as PKCS8: a
    // fixed 16-byte header for ed25519, then the seed.
    const key = createPrivateKey({
      format: "der",
      type: "pkcs8",
      key: Buffer.concat([
        Buffer.from("302e020100300506032b657004220420", "hex"),
        seed,
      ]),
    });
    expect(createPublicKey(key).export({ format: "jwk" }).x).toBe(
      publicKey.toString("base64url")
    );
    const message = Buffer.from("signed with the seed in the file");
    const signature = sign(null, message, key);
    const stated = createPublicKey({
      format: "jwk",
      key: {
        kty: "OKP",
        crv: "Ed25519",
        x: publicKey.toString("base64url"),
      },
    });
    expect(verify(null, message, stated, signature)).toBe(true);
  });

  it("mints a new key every time", () => {
    const first = newKeyPair();
    const second = newKeyPair();
    expect(second.publicKey).not.toBe(first.publicKey);
    expect(second.privateKey).not.toBe(first.privateKey);
  });
});
