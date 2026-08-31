import { describe, expect, it } from "vitest";

import { fromSerialized, toSerialized } from "../headers.ts";

describe("toSerialized", () => {
  it("produces a SerializedHeaders record from a Headers object", () => {
    const headers = new Headers({ "content-type": "application/json" });
    headers.append("x-trace", "first");
    headers.append("x-trace", "second");

    expect(toSerialized(headers)).toEqual({
      "content-type": ["application/json"],
      "x-trace": ["first, second"],
    });
  });
});

describe("fromSerialized", () => {
  it("produces a Headers object from a SerializedHeaders record", () => {
    const h = fromSerialized({
      "content-type": ["application/json"],
      "x-trace": ["first", "second"],
    });

    expect(h.get("content-type")).toBe("application/json");
    expect(h.get("x-trace")).toBe("first, second");
  });
});

describe("a Headers object round-tripped through toSerialized/fromSerialized", () => {
  it("is empty when the original was empty", () => {
    const h = fromSerialized(toSerialized(new Headers()));
    expect([...h.entries()]).toEqual([]);
  });

  it("preserves a single header", () => {
    const original = new Headers({ "content-type": "application/json" });
    const h = fromSerialized(toSerialized(original));
    expect(h.get("content-type")).toBe("application/json");
  });

  it("preserves multiple distinct headers", () => {
    const original = new Headers({
      "content-type": "application/json",
      "x-request-id": "abc-123",
      "x-connector-version": "1.2.3",
    });
    const h = fromSerialized(toSerialized(original));
    expect(h.get("content-type")).toBe("application/json");
    expect(h.get("x-request-id")).toBe("abc-123");
    expect(h.get("x-connector-version")).toBe("1.2.3");
  });

  it("preserves headers whose names need to be lowercased", () => {
    const original = new Headers({ "Content-Type": "application/json" });
    const h = fromSerialized(toSerialized(original));
    expect(h.get("content-type")).toBe("application/json");
  });

  it("preserves appended values as a comma-joined string", () => {
    // The Headers spec collapses repeated values into a single ", "-joined
    // string when read via .get(), so this is what callers should expect to
    // see on the other side of the wire.
    const original = new Headers();
    original.append("x-trace", "first");
    original.append("x-trace", "second");

    const h = fromSerialized(toSerialized(original));
    expect(h.get("x-trace")).toBe("first, second");
  });

  it("preserves a header value that itself contains commas", () => {
    const original = new Headers({
      accept: "text/html, application/json;q=0.9, */*;q=0.1",
    });

    const h = fromSerialized(toSerialized(original));
    expect(h.get("accept")).toBe(
      "text/html, application/json;q=0.9, */*;q=0.1"
    );
  });

  it("preserves a header with an empty string value", () => {
    const original = new Headers({ "x-empty": "" });

    const h = fromSerialized(toSerialized(original));
    expect(h.get("x-empty")).toBe("");
  });

  it("survives JSON serialization on the wire", () => {
    const original = new Headers({
      "content-type": "application/json",
      "x-request-id": "abc-123",
    });
    const wire = JSON.parse(JSON.stringify(toSerialized(original)));
    const h = fromSerialized(wire);
    expect(h.get("content-type")).toBe("application/json");
    expect(h.get("x-request-id")).toBe("abc-123");
  });
});
