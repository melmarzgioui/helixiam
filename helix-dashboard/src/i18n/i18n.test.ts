import { describe, it, expect } from "vitest";
import { translate, normalizeLocale } from "./i18n";
import { en, nl } from "./dictionaries";

describe("translate()", () => {
  it("resolves an English string", () => {
    expect(translate("en", "nav.users")).toBe("Users");
  });

  it("resolves the Dutch string for the same key", () => {
    expect(translate("nl", "nav.users")).toBe("Gebruikers");
  });

  it("falls back to English when the key is absent from the Dutch dict", () => {
    // Inject an en-only key for the test (dictionaries are plain objects).
    en["test.enOnly"] = "English only";
    try {
      expect(translate("nl", "test.enOnly")).toBe("English only");
    } finally {
      delete en["test.enOnly"];
    }
  });

  it("falls back to the key itself when no dictionary has it", () => {
    expect(translate("en", "totally.missing.key")).toBe("totally.missing.key");
    expect(translate("nl", "totally.missing.key")).toBe("totally.missing.key");
  });

  it("interpolates {named} params", () => {
    en["test.greet"] = "Hello {name}";
    try {
      expect(translate("en", "test.greet", { name: "Mo" })).toBe("Hello Mo");
    } finally {
      delete en["test.greet"];
    }
  });

  it("leaves an unmatched placeholder intact", () => {
    en["test.partial"] = "Hi {who}";
    try {
      expect(translate("en", "test.partial", { other: "x" })).toBe("Hi {who}");
    } finally {
      delete en["test.partial"];
    }
  });
});

describe("normalizeLocale()", () => {
  it("accepts exact supported codes", () => {
    expect(normalizeLocale("en")).toBe("en");
    expect(normalizeLocale("nl")).toBe("nl");
  });

  it("strips region subtags (nl-NL -> nl)", () => {
    expect(normalizeLocale("nl-NL")).toBe("nl");
    expect(normalizeLocale("en-US")).toBe("en");
  });

  it("degrades unknown / empty locales to en", () => {
    expect(normalizeLocale("fr")).toBe("en");
    expect(normalizeLocale("de-DE")).toBe("en");
    expect(normalizeLocale(null)).toBe("en");
    expect(normalizeLocale(undefined)).toBe("en");
    expect(normalizeLocale("")).toBe("en");
  });
});

describe("dictionary parity", () => {
  it("every English key has a Dutch counterpart", () => {
    const missing = Object.keys(en).filter((k) => !(k in nl));
    expect(missing).toEqual([]);
  });
});
