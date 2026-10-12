/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.helixiam.authorization.federation.spi.BrokeredIdentity;

import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

/**
 * The stored form of a wallet login's mapped identity, {@code WalletTransaction.verifiedIdentityJson}: written when the
 * response endpoint (Task 18) completes a transaction, read by {@link WalletIdentityProvider#callback} after the
 * response code is redeemed. Task 20 (attribute mapping and LoA) fills it; this class only fixes the shape:
 *
 * <pre>{@code
 * {"v": 1, "externalSubject": "<non-blank>", "email": "<string>"?, "emailVerified": <boolean>,
 *  "attributes": {"<name>": "<string>", ...}, "levelOfAssurance": "<eIDAS LoA URI>"?,
 *  "decision": <decision>?}
 *
 * <decision> = {"kind": "existing", "userId": "<id>", "pendingLink": {"realmId", "alias", "subject", "userId"}?}
 *            | {"kind": "provision"}
 *            | {"kind": "refused", "reason": "<WalletSubject.Reason name>"}
 * }</pre>
 *
 * Task 18: the response endpoint stores the account decision of {@link WalletLinkService#decide} with the identity
 * (server side only; it never leaves the transaction store), so the browser's callback acts on exactly that decision,
 * the {@link WalletLinkService.PendingLink} included ({@link #write(BrokeredIdentity, WalletLinkService.Decision)},
 * {@link #readLogin}). A refused login stores no identity at all ({@code externalSubject} and every attribute absent):
 * nothing of the PID is kept for a login that cannot happen.
 *
 * <p>The provider alias is not stored: the reading provider supplies it. Reading is strict ({@link StrictJson}: no
 * duplicate members) and refuses unknown members, a wrong version, a blank subject and non-string attribute values, so
 * a corrupted record never becomes a login. It never holds the {@code vp_token} or disclosures.
 */
public final class VerifiedIdentityJson {

    /** The shape version this class writes and reads. */
    public static final int VERSION = 1;

    private static final Set<String> MEMBERS = Set.of("v", "externalSubject", "email", "emailVerified", "attributes",
            "levelOfAssurance", "decision");
    private static final Set<String> PENDING_LINK_MEMBERS = Set.of("realmId", "alias", "subject", "userId");
    private static final String KIND = "kind";
    private static final String EXISTING = "existing";
    private static final String PROVISION = "provision";
    private static final String REFUSED = "refused";

    /**
     * A stored wallet login: the mapped identity ({@code null} for a {@link WalletLinkService.Decision.Refused}) and
     * the account decision made when the presentation was verified.
     */
    public record StoredLogin(BrokeredIdentity identity, WalletLinkService.Decision decision) {
    }

    private VerifiedIdentityJson() {
    }

    /** The JSON for {@code identity} (its {@code idpAlias} is left out), without a decision. */
    public static String write(final BrokeredIdentity identity) {
        return toJson(identityNode(identity));
    }

    /**
     * The JSON for a verified wallet login: {@code identity} (its {@code idpAlias} left out) and the account
     * {@code decision}. A {@link WalletLinkService.Decision.Refused} stores no identity ({@code identity} is ignored and
     * may be {@code null}); every other decision needs one.
     *
     * @throws IllegalArgumentException when a non-refused decision comes without an identity
     */
    public static String write(final BrokeredIdentity identity, final WalletLinkService.Decision decision) {
        java.util.Objects.requireNonNull(decision, "decision");
        final ObjectNode node;
        if (decision instanceof WalletLinkService.Decision.Refused) {
            node = JsonNodeFactory.instance.objectNode();
            node.put("v", VERSION);
            node.put("emailVerified", false);
            node.putObject("attributes");
        } else {
            if (identity == null) {
                throw new IllegalArgumentException("A wallet login that may sign in needs its identity");
            }
            node = identityNode(identity);
        }
        node.set("decision", decisionNode(decision));
        return toJson(node);
    }

    private static ObjectNode identityNode(final BrokeredIdentity identity) {
        final ObjectNode node = JsonNodeFactory.instance.objectNode();
        node.put("v", VERSION);
        node.put("externalSubject", identity.externalSubject());
        if (identity.email() != null) {
            node.put("email", identity.email());
        }
        node.put("emailVerified", identity.emailVerified());
        final ObjectNode attributes = node.putObject("attributes");
        if (identity.attributes() != null) {
            identity.attributes().forEach(attributes::put);
        }
        if (identity.levelOfAssurance() != null) {
            node.put("levelOfAssurance", identity.levelOfAssurance());
        }
        return node;
    }

    private static ObjectNode decisionNode(final WalletLinkService.Decision decision) {
        final ObjectNode node = JsonNodeFactory.instance.objectNode();
        switch (decision) {
            case WalletLinkService.Decision.Existing existing -> {
                node.put(KIND, EXISTING);
                node.put("userId", existing.userId());
                if (existing.pendingNumberLink() != null) {
                    final WalletLinkService.PendingLink p = existing.pendingNumberLink();
                    final ObjectNode pending = node.putObject("pendingLink");
                    pending.put("realmId", p.realmId());
                    pending.put("alias", p.alias());
                    pending.put("subject", p.subject());
                    pending.put("userId", p.userId());
                }
            }
            case WalletLinkService.Decision.Provision provision -> node.put(KIND, PROVISION);
            case WalletLinkService.Decision.Refused refused -> {
                node.put(KIND, REFUSED);
                node.put("reason", refused.reason().name());
            }
        }
        return node;
    }

    private static String toJson(final ObjectNode node) {
        try {
            return StrictJson.MAPPER.writeValueAsString(node);
        } catch (final JsonProcessingException e) {
            throw new IllegalStateException("Could not encode the verified identity", e);
        }
    }

    /**
     * The identity stored in {@code json}, for the provider {@code idpAlias}.
     *
     * @throws WalletVerificationException {@code INVALID_RESPONSE} when {@code json} is not exactly this shape
     */
    public static BrokeredIdentity read(final String idpAlias, final String json) {
        final JsonNode node = parse(json);
        return identity(idpAlias, node);
    }

    /**
     * The wallet login stored in {@code json} (identity and decision), for the provider {@code idpAlias}.
     *
     * @throws WalletVerificationException {@code INVALID_RESPONSE} when {@code json} is not exactly this shape or has
     *                                     no decision
     */
    public static StoredLogin readLogin(final String idpAlias, final String json) {
        final JsonNode node = parse(json);
        if (!node.has("decision")) {
            throw invalid();
        }
        final WalletLinkService.Decision decision = decision(node.get("decision"));
        if (decision instanceof WalletLinkService.Decision.Refused) {
            if (node.has("externalSubject") || node.has("email") || node.has("levelOfAssurance")
                    || node.get("attributes").size() != 0) {
                throw invalid();
            }
            return new StoredLogin(null, decision);
        }
        return new StoredLogin(identity(idpAlias, node), decision);
    }

    /** The strictly parsed top-level object, its shape checked except for the subject. */
    private static JsonNode parse(final String json) {
        if (json == null) {
            throw invalid();
        }
        final JsonNode node;
        try {
            node = StrictJson.MAPPER.readTree(json);
        } catch (final JsonProcessingException e) {
            throw invalid();
        }
        if (node == null || !node.isObject()) {
            throw invalid();
        }
        for (final Iterator<String> names = node.fieldNames(); names.hasNext(); ) {
            if (!MEMBERS.contains(names.next())) {
                throw invalid();
            }
        }
        if (!node.path("v").isIntegralNumber() || node.path("v").asInt() != VERSION
                || node.has("externalSubject") && !node.get("externalSubject").isTextual()
                || !node.path("emailVerified").isBoolean() || !node.path("attributes").isObject()
                || node.has("email") && !node.get("email").isTextual()
                || node.has("levelOfAssurance") && !node.get("levelOfAssurance").isTextual()) {
            throw invalid();
        }
        if (node.has("decision")) {
            decision(node.get("decision")); // a malformed decision makes the whole record invalid
        }
        return node;
    }

    private static BrokeredIdentity identity(final String idpAlias, final JsonNode node) {
        if (!node.path("externalSubject").isTextual() || node.path("externalSubject").asText().isBlank()) {
            throw invalid();
        }
        final Map<String, String> attributes = new LinkedHashMap<>();
        for (final Iterator<Map.Entry<String, JsonNode>> it = node.get("attributes").fields(); it.hasNext(); ) {
            final Map.Entry<String, JsonNode> entry = it.next();
            if (!entry.getValue().isTextual()) {
                throw invalid();
            }
            attributes.put(entry.getKey(), entry.getValue().asText());
        }
        return new BrokeredIdentity(idpAlias, node.get("externalSubject").asText(),
                node.has("email") ? node.get("email").asText() : null, node.get("emailVerified").asBoolean(),
                Collections.unmodifiableMap(attributes),
                node.has("levelOfAssurance") ? node.get("levelOfAssurance").asText() : null);
    }

    private static WalletLinkService.Decision decision(final JsonNode node) {
        if (node == null || !node.isObject() || !node.path(KIND).isTextual()) {
            throw invalid();
        }
        return switch (node.get(KIND).asText()) {
            case EXISTING -> {
                onlyMembers(node, Set.of(KIND, "userId", "pendingLink"));
                final String userId = text(node, "userId");
                WalletLinkService.PendingLink pending = null;
                if (node.has("pendingLink")) {
                    final JsonNode p = node.get("pendingLink");
                    if (!p.isObject()) {
                        throw invalid();
                    }
                    onlyMembers(p, PENDING_LINK_MEMBERS);
                    pending = new WalletLinkService.PendingLink(text(p, "realmId"), text(p, "alias"),
                            text(p, "subject"), text(p, "userId"));
                }
                yield new WalletLinkService.Decision.Existing(userId, pending);
            }
            case PROVISION -> {
                onlyMembers(node, Set.of(KIND));
                yield new WalletLinkService.Decision.Provision();
            }
            case REFUSED -> {
                onlyMembers(node, Set.of(KIND, "reason"));
                final String reason = text(node, "reason");
                try {
                    yield new WalletLinkService.Decision.Refused(WalletSubject.Reason.valueOf(reason));
                } catch (final IllegalArgumentException e) {
                    throw invalid();
                }
            }
            default -> throw invalid();
        };
    }

    private static void onlyMembers(final JsonNode node, final Set<String> allowed) {
        for (final Iterator<String> names = node.fieldNames(); names.hasNext(); ) {
            if (!allowed.contains(names.next())) {
                throw invalid();
            }
        }
    }

    private static String text(final JsonNode node, final String member) {
        if (!node.path(member).isTextual() || node.get(member).asText().isBlank()) {
            throw invalid();
        }
        return node.get(member).asText();
    }

    private static WalletVerificationException invalid() {
        return new WalletVerificationException(WalletErrorCode.INVALID_RESPONSE, "stored wallet identity is malformed");
    }
}
