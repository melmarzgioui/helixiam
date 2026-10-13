/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * Client-side copy of the server's `JwksUrlPolicy` (admin API and realm import), so the client form shows the error
 * before submit. The server stays authoritative.
 *
 * - `required`: `private_key_jwt` needs a JWKS URL.
 * - `notUrl`: not parseable as a URL (as Java's `URI` would refuse it).
 * - `notHttps`: anything but an https URL with a host; http is allowed only to `localhost` / `127.0.0.1` under the
 *   server's `dev` profile.
 */
export type JwksUrlError = "required" | "notUrl" | "notHttps";

const ILLEGAL = /[\s<>"{}|\\^`]/;
const HOSTNAME = /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*\.?$/i;
const IPV6 = /^\[[0-9a-f:.]+\]$/i;

/** The host of a hierarchical `scheme://authority...` URL, null when it has none (or none Java would accept). */
function parse(url: string): { scheme: string; host: string | null } | "notUrl" | null {
  const m = /^([a-z][a-z0-9+.-]*):\/\/([^/?#]*)(.*)$/i.exec(url);
  if (!m) return null;
  const scheme = m[1].toLowerCase();
  const authority = m[2];
  if (authority === "" && m[3] === "") return "notUrl"; // "https://": Java's URI expects an authority
  const hostPort = authority.slice(authority.lastIndexOf("@") + 1);
  let host: string;
  let port: string;
  if (hostPort.startsWith("[")) {
    const close = hostPort.indexOf("]");
    if (close < 0) return "notUrl";
    host = hostPort.slice(0, close + 1);
    port = hostPort.slice(close + 1);
  } else {
    const colon = hostPort.indexOf(":");
    host = colon < 0 ? hostPort : hostPort.slice(0, colon);
    port = colon < 0 ? "" : hostPort.slice(colon);
  }
  if (port !== "" && !/^:\d*$/.test(port)) return { scheme, host: null };
  const valid = host !== "" && (IPV6.test(host) || HOSTNAME.test(host));
  return { scheme, host: valid ? host.toLowerCase() : null };
}

/** The problem with `jwksUrl` for a client using `tokenAuthMethod`, or null. `dev`: the server runs the dev profile. */
export function jwksUrlError(jwksUrl: string, tokenAuthMethod: string, dev: boolean): JwksUrlError | null {
  const url = (jwksUrl ?? "").trim();
  if (!url) return tokenAuthMethod === "PRIVATE_KEY_JWT" ? "required" : null;
  if (ILLEGAL.test(url)) return "notUrl";
  const parsed = parse(url);
  if (parsed === "notUrl") return "notUrl";
  if (parsed && parsed.host) {
    if (parsed.scheme === "https") return null;
    if (dev && parsed.scheme === "http" && (parsed.host === "localhost" || parsed.host === "127.0.0.1")) return null;
  }
  return "notHttps";
}
