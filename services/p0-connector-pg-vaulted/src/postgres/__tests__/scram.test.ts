import { createHmac } from "node:crypto";
import { describe, expect, it } from "vitest";

import { scramVerifier } from "../scram.ts";

// The password, salt and iteration count of the example exchange in RFC
// 7677, section 3.
const PASSWORD = "pencil";
const SALT = Buffer.from("W22ZaJ0SNY7soEsUEjb6gQ==", "base64");

describe("scramVerifier", () => {
  it("is the verifier of RFC 7677's example, in the form pg_authid keeps", () => {
    expect(scramVerifier(PASSWORD, SALT)).toBe(
      "SCRAM-SHA-256$4096:W22ZaJ0SNY7soEsUEjb6gQ==$WG5d8oPm3OtcPnkdi4Uo7BkeZkBFzpcXkuLmtbsT4qY=:wfPLwcE6nTWhTAmQ7tl2KeoiWGPlZqQxSrmfPwDl2dU="
    );
  });

  it("holds the ServerKey that signs RFC 7677's example exchange", () => {
    const serverKey = scramVerifier(PASSWORD, SALT).split(":").at(-1) ?? "";
    const authMessage = [
      "n=user,r=rOprNGfwEbeRWgbNEkqO",
      "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096",
      "c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0",
    ].join(",");

    const serverSignature = createHmac(
      "sha256",
      Buffer.from(serverKey, "base64")
    )
      .update(authMessage)
      .digest("base64");

    // The `v=` of the server's final message in the RFC.
    expect(serverSignature).toBe(
      "6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4="
    );
  });
});
