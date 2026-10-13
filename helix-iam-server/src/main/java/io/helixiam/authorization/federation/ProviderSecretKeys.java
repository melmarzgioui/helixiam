/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation;

import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Task 4 (security): which identity-provider config keys are secrets, per protocol. A secret is stored encrypted in
 * {@code identity_provider.secret_json} (never in the plaintext {@code config_json}), merged back into the runtime map
 * for {@link FederationProviderFactory#fromStored}, and never returned by the admin API: the response carries
 * {@code "<key>Set": true|false} ({@link #setFlag}) instead.
 *
 * <p>Write contract (mirrors the messaging provider's {@code secret} / {@code clearSecret}): an absent, null or blank
 * value keeps the stored secret; a value replaces it; {@code "clear<Key>": "true"} ({@link #clearFlag}) with no value
 * removes it. A value together with its clear flag is rejected.
 *
 * <p>A key that is a secret for one protocol is a secret under every protocol ({@link #isSecret}): an eID key stored on
 * an {@code oidc} record, or under a protocol added later, is still never kept in clear.
 */
public final class ProviderSecretKeys {

    private static final List<String> OIDC = List.of("clientSecret");
    private static final List<String> EID = List.of("spDecryptionPrivateKey", "spSigningPrivateKey");
    /** {@code accessCertificatePrivateKey} is the dev-only software key; production keys live in the key store. */
    private static final List<String> WALLET = List.of("accessCertificatePrivateKey", "subjectPepper");
    private static final List<String> LDAP = List.of("bindPassword", "bindPw", "bindCredential");

    private static final Map<String, List<String>> BY_PROTOCOL = byProtocol();
    private static final Set<String> ALL = all();

    private ProviderSecretKeys() {
    }

    private static Map<String, List<String>> byProtocol() {
        final Map<String, List<String>> m = new LinkedHashMap<>();
        for (final String p : List.of("oidc", "social", "google", "microsoft", "github")) {
            m.put(p, OIDC);
        }
        for (final String p : List.of("eid", "digid", "eherkenning", "eidas")) {
            m.put(p, EID);
        }
        for (final String p : List.of("eudi-wallet", "openid4vp", "wallet")) {
            m.put(p, WALLET);
        }
        for (final String p : List.of("ldap", "ad")) {
            m.put(p, LDAP);
        }
        return Map.copyOf(m);
    }

    private static Set<String> all() {
        final Set<String> s = new LinkedHashSet<>();
        BY_PROTOCOL.values().forEach(s::addAll);
        return Set.copyOf(s);
    }

    /** Whether {@code key} holds a secret for {@code protocol} (or for any protocol, see the class comment). */
    public static boolean isSecret(final String protocol, final String key) {
        return key != null && (keysFor(protocol).contains(key) || ALL.contains(key));
    }

    /** The secret keys declared for {@code protocol} (case-insensitive); empty for an unknown protocol or SAML. */
    public static List<String> keysFor(final String protocol) {
        return protocol == null ? List.of() : BY_PROTOCOL.getOrDefault(protocol.toLowerCase(Locale.ROOT), List.of());
    }

    /** Every secret key of every protocol. */
    public static Set<String> allKeys() {
        return ALL;
    }

    /** The response flag for a secret: {@code clientSecret} → {@code clientSecretSet}. */
    public static String setFlag(final String key) {
        return key + "Set";
    }

    /** The write flag that removes a secret: {@code clientSecret} → {@code clearClientSecret}. */
    public static String clearFlag(final String key) {
        return "clear" + Character.toUpperCase(key.charAt(0)) + key.substring(1);
    }

    /** Whether {@code key} is a {@code <secret>Set} or {@code clear<Secret>} flag (never stored). */
    public static boolean isControlKey(final String key) {
        if (key == null) {
            return false;
        }
        for (final String secret : ALL) {
            if (key.equals(setFlag(secret)) || key.equals(clearFlag(secret))) {
                return true;
            }
        }
        return false;
    }

    /** Whether the write asks to remove {@code key}'s stored secret ({@code "clear<Key>": "true"}). */
    public static boolean clears(final Map<String, String> config, final String key) {
        return config != null && "true".equalsIgnoreCase(trim(config.get(clearFlag(key))));
    }

    /**
     * Splits a config map into its plain settings and its secrets (non-blank values only); control flags are dropped
     * from both.
     */
    public static Split split(final String protocol, final Map<String, String> config) {
        final Map<String, String> plain = new LinkedHashMap<>();
        final Map<String, String> secrets = new LinkedHashMap<>();
        if (config != null) {
            config.forEach((k, v) -> {
                if (k == null || isControlKey(k)) {
                    return;
                }
                if (isSecret(protocol, k)) {
                    if (v != null && !v.isBlank()) {
                        secrets.put(k, v);
                    }
                } else {
                    plain.put(k, v);
                }
            });
        }
        return new Split(plain, secrets);
    }

    private static String trim(final String v) {
        return v == null ? null : v.trim();
    }

    /** A config map split into plain settings and secrets. */
    public record Split(Map<String, String> plain, Map<String, String> secrets) {
    }
}
