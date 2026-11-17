import { describe, expect, it } from "vitest";

import { namesOf } from "../client.ts";

describe("namesOf", () => {
  it.each([
    [
      "( 1.3.6.1.4.1.99999.1.1 NAME 'awsRole' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
      ["awsrole"],
    ],
    ["( 2.5.4.3 NAME ( 'cn' 'commonName' ) SUP name )", ["cn", "commonname"]],
    ["( 1.2.3 DESC 'no name' )", []],
  ])("reads the names in %s", (definition, names) => {
    expect(namesOf(definition)).toEqual(names);
  });
});
