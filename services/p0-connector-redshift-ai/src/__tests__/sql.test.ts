import { ConnectorError } from "@p0security/connector-core";
import { describe, expect, it } from "vitest";

import {
  assertAgentUser,
  assertPrivilegeRole,
  quoteIdentifier,
  quoteLiteral,
  quoteUserName,
} from "../sql.ts";

describe("quoteIdentifier", () => {
  it("quotes a name and keeps its case", () => {
    expect(quoteIdentifier("Sales_2024")).toBe('"Sales_2024"');
  });

  it.each(['a"; DROP USER x; --', "a b", "1abc", "", "a.b", "x".repeat(128)])(
    "refuses %j",
    (name) => {
      expect(() => quoteIdentifier(name)).toThrow(ConnectorError);
    }
  );
});

describe("quoteUserName", () => {
  it("quotes an IAM role's user", () => {
    expect(quoteUserName("IAMR:p0-agent-r1")).toBe('"IAMR:p0-agent-r1"');
  });

  it.each(['IAMR:x"; DROP', "a b", "", "a\nb"])("refuses %j", (name) => {
    expect(() => quoteUserName(name)).toThrow(ConnectorError);
  });
});

describe("quoteLiteral", () => {
  it("doubles quotes and backslashes", () => {
    expect(quoteLiteral(`it's \\x`)).toBe(`'it''s \\\\x'`);
  });
});

describe("name guards", () => {
  it("accepts the agent namespace", () => {
    expect(assertAgentUser("IAMR:p0-agent-abc_123-x")).toBe(
      "IAMR:p0-agent-abc_123-x"
    );
    expect(assertPrivilegeRole("p0_agent_abc_123")).toBe("p0_agent_abc_123");
  });

  it.each([
    "IAMR:p0-redshift-ai-connector",
    "IAMR:P0-AGENT-ABC",
    "p0-agent-abc",
    "IAMR:p0-agent-",
    `IAMR:p0-agent-${"a".repeat(56)}`,
    "admin",
  ])("refuses user %j", (user) => {
    expect(() => assertAgentUser(user)).toThrow(ConnectorError);
  });

  it.each(["p0_connector_admin", "sys:secadmin", "p0_agent_", "p0_agent_a-b"])(
    "refuses role %j",
    (role) => {
      expect(() => assertPrivilegeRole(role)).toThrow(ConnectorError);
    }
  );
});
