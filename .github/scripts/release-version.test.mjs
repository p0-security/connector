import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

import {
  downgradeErrors,
  parseVersion,
  readServiceVersions,
  releaseVersionErrors,
  serviceVersionErrors,
  setVersion,
  writeServiceVersions,
} from "./release-version.mjs";

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

describe("releaseVersionErrors", () => {
  // The NPM tags connector-core and connector-sdk use today.
  const npmTags = ["v0.0.1", "v0.0.7", "v0.1.0"];

  it("allows the first connector release above the NPM tags", () => {
    expect(releaseVersionErrors("1.1.0", npmTags, ["1.0.0"])).toEqual([]);
  });

  it("refuses a malformed version without checking tags", () => {
    expect(releaseVersionErrors("1.1.0-rc.1", npmTags)).toEqual([
      'version must be a plain x.y.z (got "1.1.0-rc.1")',
    ]);
  });

  it("refuses a tag that already exists", () => {
    expect(releaseVersionErrors("1.1.0", [...npmTags, "v1.1.0"])).toEqual([
      "v1.1.0 already exists",
      "1.1.0 is not above v1.1.0",
    ]);
  });

  it("refuses a version below the newest tag, naming it", () => {
    expect(
      releaseVersionErrors("1.1.5", [...npmTags, "v1.2.0", "v1.10.0"])
    ).toEqual(["1.1.5 is not above v1.10.0"]);
  });

  it("compares numerically, not as strings", () => {
    expect(releaseVersionErrors("1.10.0", ["v1.9.0"])).toEqual([]);
  });

  it("allows a version above a prerelease of itself", () => {
    expect(releaseVersionErrors("1.2.0", ["v1.1.0", "v1.2.0-rc.1"])).toEqual(
      []
    );
  });

  it("refuses a version below a prerelease of a higher one", () => {
    expect(releaseVersionErrors("1.2.0", ["v1.3.0-rc.1"])).toEqual([
      "1.2.0 is not above v1.3.0-rc.1",
    ]);
  });

  it("ignores tags that are not semver", () => {
    expect(releaseVersionErrors("1.1.0", ["vnext", "v2", "v9.9"])).toEqual([]);
  });

  it("refuses a version that main's services already report", () => {
    expect(releaseVersionErrors("1.0.0", npmTags, ["1.0.0"])).toEqual([
      "1.0.0 is not above 1.0.0, which services on main already report",
    ]);
  });

  it("compares against the highest version main's services report", () => {
    expect(
      releaseVersionErrors("1.1.0", npmTags, ["1.0.0", "1.1.0", "1.0.0"])
    ).toEqual([
      "1.1.0 is not above 1.1.0, which services on main already report",
    ]);
  });
});

describe("setVersion", () => {
  const manifest = `{
  "name": "@p0security/p0-connector-example",
  "version": "1.0.0",
  "files": ["dist"],
  "dependencies": {
    "nested": { "version": "9.9.9" }
  }
}
`;

  it("rewrites only the top-level version line", () => {
    expect(setVersion(manifest, "1.1.0")).toBe(
      manifest.replace('"version": "1.0.0"', '"version": "1.1.0"')
    );
  });

  it("throws when there is no top-level version", () => {
    expect(() => setVersion('{\n  "name": "x"\n}\n', "1.1.0")).toThrow(
      /found 0/
    );
  });
});

describe("service versions", () => {
  const makeRepo = (versions) => {
    const root = mkdtempSync(join(tmpdir(), "release-version-"));
    for (const [name, version] of Object.entries(versions)) {
      mkdirSync(join(root, "services", name), { recursive: true });
      writeFileSync(
        join(root, "services", name, "package.json"),
        `{\n  "name": "${name}",\n  "version": "${version}",\n  "files": ["dist"]\n}\n`
      );
    }
    // A directory without a package.json is not a service.
    mkdirSync(join(root, "services", "not-a-service"), { recursive: true });
    // Neither the root nor packages/* are rewritten.
    mkdirSync(join(root, "packages", "connector-core"), { recursive: true });
    writeFileSync(
      join(root, "packages", "connector-core", "package.json"),
      '{\n  "version": "0.1.0"\n}\n'
    );
    writeFileSync(join(root, "package.json"), '{\n  "version": "0.0.0"\n}\n');
    return root;
  };

  it("writes the version to every service and nothing else", () => {
    const root = makeRepo({ a: "1.0.0", b: "1.0.0" });
    const paths = writeServiceVersions("1.1.0", root);

    expect(paths).toHaveLength(2);
    expect(readServiceVersions(root).map((entry) => entry.version)).toEqual([
      "1.1.0",
      "1.1.0",
    ]);
    expect(serviceVersionErrors("1.1.0", root)).toEqual([]);
    expect(readFileSync(join(root, "package.json"), "utf8")).toContain("0.0.0");
    expect(
      readFileSync(
        join(root, "packages", "connector-core", "package.json"),
        "utf8"
      )
    ).toContain("0.1.0");
  });

  it("names every service that disagrees", () => {
    const root = makeRepo({ a: "1.1.0", b: "1.0.0" });

    expect(serviceVersionErrors("1.1.0", root)).toEqual([
      `${join(root, "services", "b", "package.json")} is at 1.0.0, not 1.1.0`,
    ]);
  });

  it("refuses to lower a service's version", () => {
    const root = makeRepo({ a: "1.1.0", b: "1.2.0" });

    expect(downgradeErrors("1.1.0", root)).toEqual([
      `${join(root, "services", "b", "package.json")} is at 1.2.0, above 1.1.0; refusing to lower it`,
    ]);
    expect(downgradeErrors("1.2.0", root)).toEqual([]);
  });

  it("fails when there are no services", () => {
    const root = makeRepo({});

    expect(serviceVersionErrors("1.1.0", root)).toEqual([
      "found no services/*/package.json",
    ]);
  });
});
