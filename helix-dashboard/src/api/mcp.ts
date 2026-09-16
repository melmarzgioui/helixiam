/** MCP (Model Context Protocol) authorization helpers — pure functions behind the console's MCP screen.
 *
 * Helix is the OAuth 2.1 authorization server for MCP: an MCP server is an OAuth resource server, and the
 * agent calling it is an OAuth client. There is no MCP-specific backend — MCP callers are ordinary agents
 * (holding an `mcp`/`mcp:*` scope or role) bound to clients, and the discovery/DCR endpoints already exist.
 * These helpers surface that on one page and generate the RFC 9728 metadata a resource server must publish.
 */
import type { Agent } from "./agents";
import { parseCsv } from "./agents";

/** The scope/role name that marks an agent as an MCP caller: `mcp` itself or any `mcp:<tool>`. */
export const MCP_SCOPE_PREFIX = "mcp";

/** The well-known path a resource server publishes its RFC 9728 metadata at. */
export const PROTECTED_RESOURCE_PATH = "/.well-known/oauth-protected-resource";

const trimSlash = (s: string) => (s ?? "").replace(/\/+$/, "");

/** Strip a client-role's `clientId/` prefix so `kubedna-cli/mcp:tools` compares as `mcp:tools`. */
function bareRole(token: string): string {
  const slash = token.indexOf("/");
  return slash >= 0 ? token.slice(slash + 1) : token;
}

/** The MCP-related scope/role tokens on an agent (deduped) — `mcp` or `mcp:*`, across scopes and roles. */
export function mcpTokens(agent: Agent): string[] {
  const all = [...parseCsv(agent.scopes), ...parseCsv(agent.roles)];
  const hits = all
    .map(bareRole)
    .filter((bare) => bare === MCP_SCOPE_PREFIX || bare.startsWith(`${MCP_SCOPE_PREFIX}:`));
  return Array.from(new Set(hits));
}

/** An agent is MCP-capable when it carries at least one `mcp`/`mcp:*` scope or role. */
export function isMcpAgent(agent: Agent): boolean {
  return mcpTokens(agent).length > 0;
}

/** The subset of agents that can call an MCP server. */
export function mcpAgents(agents: Agent[]): Agent[] {
  return agents.filter(isMcpAgent);
}

/** The Dynamic Client Registration endpoint (RFC 7591) for a realm issuer. */
export function registrationEndpoint(issuer: string): string {
  return `${trimSlash(issuer)}/connect/register`;
}

/** The RFC 9728 Protected Resource Metadata URL a client fetches for a given resource server. */
export function protectedResourceMetadataUrl(resource: string): string {
  return `${trimSlash(resource)}${PROTECTED_RESOURCE_PATH}`;
}

/** The RFC 9728 Protected Resource Metadata document a resource server must publish (mirrors the backend). */
export interface ProtectedResourceMetadata {
  resource: string;
  authorization_servers: string[];
  scopes_supported: string[];
  bearer_methods_supported: string[];
}

/** Build the RFC 9728 document naming this realm as the authorization server for `resource`. */
export function protectedResourceMetadata(resource: string, issuer: string, scopes: string[]): ProtectedResourceMetadata {
  return {
    resource: trimSlash(resource),
    authorization_servers: [trimSlash(issuer)],
    scopes_supported: scopes.length ? scopes : ["openid", "mcp:tools"],
    bearer_methods_supported: ["header"],
  };
}

/** The `WWW-Authenticate` challenge a resource server returns on an unauthenticated call. */
export function wwwAuthenticateChallenge(resource: string): string {
  return `Bearer resource_metadata="${protectedResourceMetadataUrl(resource)}"`;
}

/** Pure validator for the "protect your MCP server" generator: the resource must be an http(s) URL. */
export function validateResourceUrl(url: string): string[] {
  return /^https?:\/\/.+/.test((url ?? "").trim()) ? [] : ["resource"];
}
