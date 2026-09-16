import { describe, it, expect } from "vitest";
import { clientLabel, looksLikeUuid } from "./clients";
import { applicationLabel } from "./applications";

describe("UUID-safe labels — never show a UUID as a name", () => {
  it("detects bare + embedded UUIDs", () => {
    expect(looksLikeUuid("5bcd8361-ca2b-4716-86b6-728e81fc9d58")).toBe(true);
    expect(looksLikeUuid("dcr-5bcd8361-ca2b-4716-86b6-728e81fc9d58")).toBe(true);
    expect(looksLikeUuid("web-app")).toBe(false);
    expect(looksLikeUuid(null)).toBe(false);
  });

  it("clientLabel prefers the name, then a non-UUID clientId, never a UUID", () => {
    expect(clientLabel({ name: "Web App", clientId: "dcr-5bcd8361-ca2b-4716-86b6-728e81fc9d58" })).toBe("Web App");
    expect(clientLabel({ name: null, clientId: "spa-app" })).toBe("spa-app");
    expect(clientLabel({ name: " ", clientId: "dcr-5bcd8361-ca2b-4716-86b6-728e81fc9d58" })).toBe("Unnamed client");
    expect(clientLabel({ name: null, clientId: "5bcd8361-ca2b-4716-86b6-728e81fc9d58" })).toBe("Unnamed client");
  });

  it("applicationLabel prefers displayName, then a non-UUID name, never a UUID", () => {
    expect(applicationLabel({ name: "web-app", displayName: "Web App" })).toBe("Web App");
    expect(applicationLabel({ name: "web-app", displayName: null })).toBe("web-app");
    expect(applicationLabel({ name: "dcr-5bcd8361-ca2b-4716-86b6-728e81fc9d58", displayName: null })).toBe("Unnamed application");
    expect(applicationLabel({ name: "5bcd8361-ca2b-4716-86b6-728e81fc9d58", displayName: "  " })).toBe("Unnamed application");
  });
});
