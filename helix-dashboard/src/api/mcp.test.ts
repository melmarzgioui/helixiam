/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { describe, it, expect } from "vitest";
import {
  mcpTokens,
  isMcpAgent,
  mcpAgents,
  registrationEndpoint,
  protectedResourceMetadataUrl,
  protectedResourceMetadata,
  wwwAuthenticateChallenge,
  validateResourceUrl,
} from "./mcp";
import type { Agent } from "./agents";

function agent(over: Partial<Agent>): Agent {
  return {
    id: "a1", realmId: "master", name: "bot", displayName: null, description: null,
    owner: "alice@acme.example", status: "ACTIVE", authMethod: "SECRET", clientId: "c1",
    scopes: null, roles: null, enabled: true, createdAt: null, expiresAt: null, lastUsedAt: null,
    ...over,
  };
}

describe("mcpTokens", () => {
  it("collects mcp scopes and roles, stripping a client-role's clientId prefix", () => {
    const a = agent({ scopes: "openid mcp:tools", roles: "auditor kubedna-cli/mcp:invoke" });
    expect(mcpTokens(a).sort()).toEqual(["mcp:invoke", "mcp:tools"]);
  });
  it("matches the bare `mcp` token too, and ignores unrelated scopes", () => {
    expect(mcpTokens(agent({ scopes: "mcp email" }))).toEqual(["mcp"]);
    expect(mcpTokens(agent({ scopes: "mcpx:tools reporting" }))).toEqual([]);
  });
  it("is empty when there are no scopes or roles", () => {
    expect(mcpTokens(agent({}))).toEqual([]);
  });
});

describe("isMcpAgent / mcpAgents", () => {
  it("flags only agents carrying an mcp scope or role", () => {
    const yes = agent({ id: "y", scopes: "openid mcp:tools" });
    const no = agent({ id: "n", scopes: "openid email" });
    expect(isMcpAgent(yes)).toBe(true);
    expect(isMcpAgent(no)).toBe(false);
    expect(mcpAgents([yes, no]).map((a) => a.id)).toEqual(["y"]);
  });
});

describe("endpoint helpers", () => {
  it("derives the DCR registration endpoint from the issuer (tolerating a trailing slash)", () => {
    expect(registrationEndpoint("http://localhost:8083/realms/master")).toBe("http://localhost:8083/realms/master/connect/register");
    expect(registrationEndpoint("http://localhost:8083/realms/master/")).toBe("http://localhost:8083/realms/master/connect/register");
  });
  it("builds the RFC 9728 protected-resource-metadata URL for a resource server", () => {
    expect(protectedResourceMetadataUrl("http://localhost:9800")).toBe("http://localhost:9800/.well-known/oauth-protected-resource");
    expect(protectedResourceMetadataUrl("http://localhost:9800/")).toBe("http://localhost:9800/.well-known/oauth-protected-resource");
  });
});

describe("protectedResourceMetadata", () => {
  it("builds the RFC 9728 document naming the realm as authorization server", () => {
    expect(protectedResourceMetadata("http://localhost:9800/", "http://localhost:8083/realms/master", ["openid", "mcp:tools"])).toEqual({
      resource: "http://localhost:9800",
      authorization_servers: ["http://localhost:8083/realms/master"],
      scopes_supported: ["openid", "mcp:tools"],
      bearer_methods_supported: ["header"],
    });
  });
  it("falls back to default scopes when none are supplied", () => {
    expect(protectedResourceMetadata("http://x", "http://as", []).scopes_supported).toEqual(["openid", "mcp:tools"]);
  });
});

describe("wwwAuthenticateChallenge", () => {
  it("points the client at the resource's metadata document", () => {
    expect(wwwAuthenticateChallenge("http://localhost:9800")).toBe(
      'Bearer resource_metadata="http://localhost:9800/.well-known/oauth-protected-resource"',
    );
  });
});

describe("validateResourceUrl", () => {
  it("accepts an http(s) URL and rejects anything else", () => {
    expect(validateResourceUrl("http://localhost:9800")).toEqual([]);
    expect(validateResourceUrl("https://mcp.acme.example")).toEqual([]);
    expect(validateResourceUrl("mcp.acme.example")).toEqual(["resource"]);
    expect(validateResourceUrl("")).toEqual(["resource"]);
  });
});
