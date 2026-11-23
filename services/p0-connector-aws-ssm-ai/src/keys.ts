import { generateKeyPairSync, randomBytes } from "node:crypto";

const KEY_TYPE = "ssh-ed25519";

const BEGIN = "-----BEGIN OPENSSH PRIVATE KEY-----";
const END = "-----END OPENSSH PRIVATE KEY-----";

/** OpenSSH wraps the base64 of a private key at this many characters. */
const LINE_LENGTH = 70;

/**
 * The format pads the private section to a multiple of the cipher's block
 * size.
 */
const BLOCK_SIZE = 8;

const uint32 = (value: number) => {
  const bytes = Buffer.alloc(4);
  bytes.writeUInt32BE(value);
  return bytes;
};

/** One field as OpenSSH writes it: its length, then its bytes. */
const field = (value: Buffer | string) => {
  const bytes = typeof value === "string" ? Buffer.from(value) : value;
  return Buffer.concat([uint32(bytes.length), bytes]);
};

export type KeyPair = {
  /** `ssh-ed25519 <base64>`, with no comment. */
  publicKey: string;
  /** The private key in OpenSSH's own format, not encrypted. A secret. */
  privateKey: string;
};

/**
 * Writes an ed25519 key pair in the formats `ssh` reads, from the key's
 * 32-byte seed and 32-byte public key.
 *
 * Node exports a private key as PKCS8, which OpenSSH reads only from 9.9 on.
 * So this writes the private key by hand in OpenSSH's `openssh-key-v1`
 * format (PROTOCOL.key in OpenSSH's source), which every OpenSSH since 6.5
 * reads.
 *
 * `check` is the format's check number. OpenSSH picks it at random and only
 * compares its two copies.
 */
export const toOpenSshKeyPair = (
  seed: Buffer,
  publicKey: Buffer,
  check: Buffer = randomBytes(4)
): KeyPair => {
  const publicBlob = Buffer.concat([field(KEY_TYPE), field(publicKey)]);
  const unpadded = Buffer.concat([
    check,
    check,
    field(KEY_TYPE),
    field(publicKey),
    // OpenSSH keeps the public key after the seed.
    field(Buffer.concat([seed, publicKey])),
    // No comment.
    field(""),
  ]);
  const padding = Buffer.from(
    Array.from(
      { length: (BLOCK_SIZE - (unpadded.length % BLOCK_SIZE)) % BLOCK_SIZE },
      (_, index) => index + 1
    )
  );
  const body = Buffer.concat([
    Buffer.from("openssh-key-v1\0"),
    // Cipher, key derivation and its options: the key is not encrypted.
    field("none"),
    field("none"),
    field(""),
    // One key.
    uint32(1),
    field(publicBlob),
    field(Buffer.concat([unpadded, padding])),
  ]);
  const lines =
    body.toString("base64").match(new RegExp(`.{1,${LINE_LENGTH}}`, "g")) ?? [];
  return {
    publicKey: `${KEY_TYPE} ${publicBlob.toString("base64")}`,
    privateKey: `${[BEGIN, ...lines, END].join("\n")}\n`,
  };
};

/** Mints a new ed25519 key pair. The private key exists only in memory. */
export const newKeyPair = (): KeyPair => {
  const { privateKey } = generateKeyPairSync("ed25519");
  const { d, x } = privateKey.export({ format: "jwk" });
  if (!d || !x) {
    throw new Error("Node returned an ed25519 key without its two halves");
  }
  return toOpenSshKeyPair(
    Buffer.from(d, "base64url"),
    Buffer.from(x, "base64url")
  );
};
