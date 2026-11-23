import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

import {
  consistencyErrors,
  parseTags,
  parseVersion,
  readVersions,
  tagErrors,
  tagPrefixErrors,
  versionErrors,
} from "./release-version.mjs";

describe("tagPrefixErrors", () => {
  it.each(["connector", "npm"])("accepts %s", (prefix) => {
    expect(tagPrefixErrors(prefix)).toEqual([]);
  });

  it.each(["", "sdk", "Connector", "connector/", "toString", "__proto__"])(
    "refuses %j",
    (prefix) => {
      expect(tagPrefixErrors(prefix)).toEqual([
        `tag prefix must be one of connector, npm (got "${prefix}")`,
      ]);
    }
  );
});

describe("parseVersion", () => {
  it.each(["1.1.0", "0.0.0", "10.20.30"])("accepts %s", (version) => {
    expect(parseVersion(version)).not.toBeNull();
  });

  it.each([
    "",
    "1.1",
    "1.1.0.0",
    "v1.1.0",
    "01.1.0",
    "1.01.0",
    "1.1.0-rc.1",
    "1.1.0+build",
    " 1.1.0",
    "1.1.0\n",
  ])("rejects %j", (version) => {
    expect(parseVersion(version)).toBeNull();
  });
});

describe("parseTags", () => {
  it("uses the peeled commit of an annotated tag", () => {
    expect(
      parseTags(
        [
          "aaa\trefs/tags/connector/v1.1.0",
          "bbb\trefs/tags/npm/v0.2.0",
          "ccc\trefs/tags/npm/v0.2.0^{}",
          "",
        ].join("\n")
      )
    ).toEqual([
      { name: "connector/v1.1.0", commit: "aaa" },
      { name: "npm/v0.2.0", commit: "ccc" },
    ]);
  });
});

describe("tagErrors", () => {
  const tags = [
    { name: "v0.0.7", commit: "old" },
    { name: "connector/v1.1.0", commit: "c110" },
    { name: "connector/v1.10.0", commit: "c1100" },
    { name: "npm/v0.2.0", commit: "n020" },
  ];

  it("allows a version above every tag with the same prefix", () => {
    expect(tagErrors("connector", "1.11.0", "new", tags)).toEqual([]);
  });

  it("ignores tags with another prefix or none", () => {
    expect(tagErrors("npm", "0.3.0", "new", tags)).toEqual([]);
    expect(tagErrors("npm", "0.0.1", "new", [])).toEqual([]);
  });

  it("allows the first tag of a prefix", () => {
    expect(tagErrors("npm", "0.1.0", "new", tags.slice(0, 3))).toEqual([]);
  });

  it("refuses a version below the newest same-prefix tag, naming it", () => {
    expect(tagErrors("connector", "1.9.0", "new", tags)).toEqual([
      "1.9.0 is not above connector/v1.10.0",
    ]);
  });

  it("refuses a tag that names another commit", () => {
    expect(tagErrors("connector", "1.10.0", "new", tags)).toEqual([
      "connector/v1.10.0 already tags c1100, not new",
    ]);
  });

  it("allows a tag that already names the commit, as a re-run", () => {
    expect(tagErrors("connector", "1.1.0", "c110", tags)).toEqual([]);
  });

  it("refuses a malformed version", () => {
    expect(tagErrors("connector", "1.2.0-rc.1", "new", tags)).toEqual([
      'version must be a plain x.y.z (got "1.2.0-rc.1")',
    ]);
  });
});

describe("package.json versions", () => {
  const makeRepo = ({ services, core = "0.1.0", sdk = "0.1.0" }) => {
    const root = mkdtempSync(join(tmpdir(), "release-version-"));
    const write = (dir, version) => {
      mkdirSync(join(root, dir), { recursive: true });
      writeFileSync(
        join(root, dir, "package.json"),
        `{\n  "name": "${dir}",\n  "version": "${version}"\n}\n`
      );
    };
    for (const [name, version] of Object.entries(services)) {
      write(join("services", name), version);
    }
    write(join("packages", "connector-core"), core);
    write(join("packages", "connector-sdk"), sdk);
    write(".", "0.0.0");
    // A directory without a package.json is not a service.
    mkdirSync(join(root, "services", "not-a-service"), { recursive: true });
    return root;
  };

  it("reads each prefix's files, relative to the root", () => {
    const root = makeRepo({ services: { b: "1.0.0", a: "1.0.0" } });

    expect(readVersions("connector", root)).toEqual([
      { path: join("services", "a", "package.json"), version: "1.0.0" },
      { path: join("services", "b", "package.json"), version: "1.0.0" },
    ]);
    expect(readVersions("npm", root).map((entry) => entry.path)).toEqual([
      join("packages", "connector-core", "package.json"),
      join("packages", "connector-sdk", "package.json"),
    ]);
  });

  it("names every file not at the version", () => {
    const root = makeRepo({ services: { a: "1.1.0", b: "1.0.0" } });

    expect(versionErrors("connector", "1.1.0", root)).toEqual([
      `${join("services", "b", "package.json")} is at 1.0.0, not 1.1.0`,
    ]);
    expect(versionErrors("npm", "0.1.0", root)).toEqual([]);
  });

  it("fails when there are no services", () => {
    const root = makeRepo({ services: {} });

    expect(versionErrors("connector", "1.1.0", root)).toEqual([
      "found no connector package.json files",
    ]);
  });

  it("names the files off the most common version", () => {
    const root = makeRepo({
      services: { a: "1.1.0", b: "1.1.0", c: "1.0.0" },
      sdk: "0.2.0",
    });

    expect(consistencyErrors("connector", root)).toEqual([
      `${join("services", "c", "package.json")} is at 1.0.0, but the other connector package.json files are at 1.1.0`,
    ]);
    expect(consistencyErrors("npm", root)).toHaveLength(1);
  });

  it("passes when every file agrees", () => {
    const root = makeRepo({ services: { a: "1.0.0", b: "1.0.0" } });

    expect(consistencyErrors("connector", root)).toEqual([]);
    expect(consistencyErrors("npm", root)).toEqual([]);
  });
});
