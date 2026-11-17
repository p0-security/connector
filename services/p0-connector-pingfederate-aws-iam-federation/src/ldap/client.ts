import { Client, type Entry, NoSuchObjectError } from "ldapts";

import type { App } from "../account.ts";

export const LDAP_TIMEOUT_MS = 10_000;

export type AttributeType = {
  /** The definition as the schema writes it, such as `( 1.2.3 NAME 'awsRole' … )`. */
  definition: string;
  singleValued: boolean;
};

export type Directory = {
  entryExists(dn: string): Promise<boolean>;
  /** The schema's definition of the attribute `name`, or `undefined` when the schema has none. */
  findAttributeType(name: string): Promise<AttributeType | undefined>;
  close(): Promise<void>;
};

const toStrings = (value: Entry[string] | undefined): string[] => {
  if (value === undefined) return [];
  const values = Array.isArray(value) ? value : [value];
  return values.map((v) => (typeof v === "string" ? v : v.toString("utf8")));
};

const NAMES = /\bNAME\s+(?:'([^']*)'|\(([^)]*)\))/i;

/** The names in an RFC 4512 attribute type definition, lower case. */
export const namesOf = (definition: string): string[] => {
  const match = definition.match(NAMES);
  if (match === null) return [];
  const names =
    match[1] !== undefined
      ? [match[1]]
      : (match[2]?.match(/'[^']*'/g) ?? []).map((name) => name.slice(1, -1));
  return names.map((name) => name.toLowerCase());
};

const directoryOf = (client: Client): Directory => ({
  entryExists: async (dn) => {
    try {
      // `1.1` asks for no attributes.
      await client.search(dn, {
        scope: "base",
        filter: "(objectClass=*)",
        attributes: ["1.1"],
      });
      return true;
    } catch (error) {
      if (error instanceof NoSuchObjectError) return false;
      throw error;
    }
  },
  findAttributeType: async (name) => {
    const { searchEntries: rootDse } = await client.search("", {
      scope: "base",
      filter: "(objectClass=*)",
      attributes: ["subschemaSubentry"],
    });
    const [subschema] = toStrings(rootDse[0]?.subschemaSubentry);
    if (subschema === undefined) return undefined;
    const { searchEntries: schema } = await client.search(subschema, {
      scope: "base",
      filter: "(objectClass=subschema)",
      attributes: ["attributeTypes"],
    });
    const wanted = name.toLowerCase();
    const definition = toStrings(schema[0]?.attributeTypes).find((type) =>
      namesOf(type).includes(wanted)
    );
    return definition === undefined
      ? undefined
      : { definition, singleValued: /\bSINGLE-VALUE\b/.test(definition) };
  },
  close: () => client.unbind().catch(() => undefined),
});

/**
 * Connects to the user store over LDAPS and binds as the bind account. Call
 * `close` when done, also after a failure.
 */
export const connectDirectory = async (
  input: Pick<App, "bindDn" | "caCertificate" | "directoryUrl">,
  password: string
): Promise<Directory> => {
  const client = new Client({
    url: input.directoryUrl,
    timeout: LDAP_TIMEOUT_MS,
    connectTimeout: LDAP_TIMEOUT_MS,
    tlsOptions:
      input.caCertificate === undefined ? {} : { ca: input.caCertificate },
  });
  const directory = directoryOf(client);
  try {
    await client.bind(input.bindDn, password);
  } catch (error) {
    await directory.close();
    throw error;
  }
  return directory;
};
