/** Reads OpenSSH's length-prefixed fields off the front of a buffer. */
const reader = (buffer: Buffer) => {
  let offset = 0;
  const take = (length: number) => {
    const bytes = buffer.subarray(offset, offset + length);
    offset += length;
    return bytes;
  };
  const uint32 = () => take(4).readUInt32BE();
  return {
    take,
    uint32,
    field: () => take(uint32()),
    rest: () => buffer.subarray(offset),
  };
};

/**
 * Takes an `openssh-key-v1` private key apart, as PROTOCOL.key in OpenSSH's
 * source lays it out, so a test can check each part.
 */
export const parseOpenSshPrivateKey = (pem: string) => {
  const lines = pem.split("\n");
  const outer = reader(Buffer.from(lines.slice(1, -2).join(""), "base64"));
  const magic = outer.take(15).toString("latin1");
  const cipher = outer.field().toString();
  const kdf = outer.field().toString();
  const kdfOptions = outer.field();
  const nKeys = outer.uint32();
  const publicBlob = outer.field();
  const privateSection = outer.field();
  const inner = reader(privateSection);
  return {
    lines,
    magic,
    cipher,
    kdf,
    kdfOptions,
    nKeys,
    publicBlob,
    privateSection,
    trailing: outer.rest(),
    check: [inner.uint32(), inner.uint32()],
    keyType: inner.field().toString(),
    publicKey: inner.field(),
    /** The seed, then the public key again. */
    privateKey: inner.field(),
    comment: inner.field().toString(),
    padding: [...inner.rest()],
  };
};

/** The `ssh-ed25519 <base64>` line for the public half of a private key. */
export const publicKeyOf = (pem: string) =>
  `ssh-ed25519 ${parseOpenSshPrivateKey(pem).publicBlob.toString("base64")}`;
