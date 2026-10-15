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
 * <p><b>Task 21b: a link record.</b> A {@code LINK} transaction (account console) stores no identity and no decision,
 * only the resolved subject's hashes, for the console's callback to link:
 * <pre>{@code
 * {"v": 1, "emailVerified": false, "attributes": {}, "link": <link>}
 *
 * <link> = {"kind": "number", "subject": "<hex>", "tuple": "<hex>"?}
 *        | {"kind": "tuple", "subject": "<hex>"}
 *        | {"kind": "unavailable", "reason": "<WalletSubject.Reason name>"}
 * }</pre>
 * ({@link #writeLink}, {@link #readLink}). A link record is never a login ({@link #read} and {@link #readLogin} refuse
 * it) and a login record is never a link.
 *
 * <p>The provider alias is not stored: the reading provider supplies it. Reading is strict ({@link StrictJson}: no
 * duplicate members) and refuses unknown members, a wrong version, a blank subject and non-string attribute values, so
 * a corrupted record never becomes a login. It never holds the {@code vp_token} or disclosures.
 */
public final class VerifiedIdentityJson {

    /** The shape version this class writes and reads. */
    public static final int VERSION = 1;

    private static final Set<String> MEMBERS = Set.of("v", "externalSubject", "email", "emailVerified", "attributes",
            "levelOfAssurance", "decision", "link", "verify", "format", "issuerDn");
    private static final Set<String> PENDING_LINK_MEMBERS = Set.of("realmId", "alias", "subject", "userId");
    private static final String KIND = "kind";
    private static final String EXISTING = "existing";
    private static final String PROVISION = "provision";
    private static final String REFUSED = "refused";
    private static final String LINK = "link";
    private static final String NUMBER = "number";
    private static final String TUPLE = "tuple";
    private static final String UNAVAILABLE = "unavailable";
    private static final String VERIFY = "verify";

    /**
     * A stored wallet login: the mapped identity ({@code null} for a {@link WalletLinkService.Decision.Refused}) and
     * the account decision made when the presentation was verified.
     *
     * <p>Task 22 audit context: {@code format} (the presentation's {@code dc+sd-jwt}/{@code mso_mdoc}) and
     * {@code issuerDn} (the issuer certificate's subject DN — public certificate data, never a PID value) round-trip
     * through the stored JSON ({@link #write(BrokeredIdentity, WalletLinkService.Decision, String, String)}); they are
     * {@code null} when not supplied. {@code transactionId} never does — it is already known to whoever redeemed the
     * transaction, so it is attached afterwards with {@link #withTransactionId}, never serialized.
     */
    public record StoredLogin(BrokeredIdentity identity, WalletLinkService.Decision decision, String format,
            String issuerDn, String transactionId) {

        /** Back-compat: no format/issuerDn/transactionId. */
        public StoredLogin(final BrokeredIdentity identity, final WalletLinkService.Decision decision) {
            this(identity, decision, null, null, null);
        }

        /** This login's transaction id attached (the redeeming provider's own knowledge, never from the JSON). */
        public StoredLogin withTransactionId(final String transactionId) {
            return new StoredLogin(identity, decision, format, issuerDn, transactionId);
        }
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
        return write(identity, decision, null, null);
    }

    /**
     * As {@link #write(BrokeredIdentity, WalletLinkService.Decision)}, additionally carrying the verified
     * presentation's {@code format} and issuer certificate {@code issuerDn} (Task 22 audit context; both nullable,
     * e.g. when not supplied). Stored even for a {@link WalletLinkService.Decision.Refused}: the presentation was
     * still cryptographically verified, only the account decision refused.
     */
    public static String write(final BrokeredIdentity identity, final WalletLinkService.Decision decision,
            final String format, final String issuerDn) {
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
        if (format != null) {
            node.put("format", format);
        }
        if (issuerDn != null) {
            node.put("issuerDn", issuerDn);
        }
        node.set("decision", decisionNode(decision));
        return toJson(node);
    }

    /**
     * Task 21b: the JSON for a verified LINK transaction: only the resolved {@code subject} (its HMAC values, or why
     * there is none), no identity and no decision.
     */
    public static String writeLink(final WalletSubject subject) {
        java.util.Objects.requireNonNull(subject, "subject");
        final ObjectNode node = JsonNodeFactory.instance.objectNode();
        node.put("v", VERSION);
        node.put("emailVerified", false);
        node.putObject("attributes");
        final ObjectNode link = node.putObject(LINK);
        switch (subject) {
            case WalletSubject.AdminNumber number -> {
                link.put(KIND, NUMBER);
                link.put("subject", number.value());
                if (number.tupleValue() != null) {
                    link.put(TUPLE, number.tupleValue());
                }
            }
            case WalletSubject.Tuple tuple -> {
                link.put(KIND, TUPLE);
                link.put("subject", tuple.value());
            }
            case WalletSubject.Unavailable unavailable -> {
                link.put(KIND, UNAVAILABLE);
                link.put("reason", unavailable.reason().name());
            }
        }
        return toJson(node);
    }

    /**
     * Task 21b: the subject stored in a link record ({@link #writeLink}).
     *
     * @throws WalletVerificationException {@code INVALID_RESPONSE} when {@code json} is not exactly a link record
     */
    public static WalletSubject readLink(final String json) {
        final JsonNode node = parse(json);
        if (!node.has(LINK) || node.has(VERIFY) || node.has("decision") || node.has("externalSubject") || node.has("email")
                || node.has("levelOfAssurance") || node.get("attributes").size() != 0) {
            throw invalid();
        }
        final JsonNode link = node.get(LINK);
        if (!link.isObject() || !link.path(KIND).isTextual()) {
            throw invalid();
        }
        return switch (link.get(KIND).asText()) {
            case NUMBER -> {
                onlyMembers(link, Set.of(KIND, "subject", TUPLE));
                yield new WalletSubject.AdminNumber(text(link, "subject"), link.has(TUPLE) ? text(link, TUPLE) : null);
            }
            case TUPLE -> {
                onlyMembers(link, Set.of(KIND, "subject"));
                yield new WalletSubject.Tuple(text(link, "subject"));
            }
            case UNAVAILABLE -> {
                onlyMembers(link, Set.of(KIND, "reason"));
                try {
                    yield new WalletSubject.Unavailable(WalletSubject.Reason.valueOf(text(link, "reason")));
                } catch (final IllegalArgumentException e) {
                    throw invalid();
                }
            }
            default -> throw invalid();
        };
    }

    /**
     * Verify-only mode: what a verified {@code VERIFY} transaction keeps for the {@code eudi-wallet-verify} flow step.
     * The subject hashes (computed as the linked login connection computes them) to bind the wallet to the signed-in
     * user, the released claims ({@link WalletVerifiedClaims}, already reduced to the allow-list), the level of
     * assurance, and the audit context. No identity, no decision, no other PID value.
     *
     * @param numberSubject the administrative-number HMAC, or {@code null}
     * @param tupleSubject  the attribute-tuple HMAC (only when the linked connection accepts weak subjects), or
     *                      {@code null}
     * @param claims        released claim name to a string or boolean value, in release order
     */
    public record Verification(String numberSubject, String tupleSubject, Map<String, Object> claims,
                               String levelOfAssurance, String format, String issuerDn) {
    }

    /** The JSON for a verified {@code VERIFY} transaction (see {@link Verification}). */
    public static String writeVerify(final WalletSubject subject, final Map<String, Object> claims,
                                     final String levelOfAssurance, final String format, final String issuerDn) {
        java.util.Objects.requireNonNull(subject, "subject");
        java.util.Objects.requireNonNull(levelOfAssurance, "levelOfAssurance");
        final ObjectNode node = JsonNodeFactory.instance.objectNode();
        node.put("v", VERSION);
        node.put("emailVerified", false);
        node.putObject("attributes");
        if (format != null) {
            node.put("format", format);
        }
        if (issuerDn != null) {
            node.put("issuerDn", issuerDn);
        }
        final ObjectNode verify = node.putObject(VERIFY);
        switch (subject) {
            case WalletSubject.AdminNumber number -> {
                verify.put(NUMBER, number.value());
                if (number.tupleValue() != null) {
                    verify.put(TUPLE, number.tupleValue());
                }
            }
            case WalletSubject.Tuple tuple -> verify.put(TUPLE, tuple.value());
            case WalletSubject.Unavailable unavailable -> {
                // no subject: the step refuses the binding
            }
        }
        final ObjectNode out = verify.putObject("claims");
        if (claims != null) {
            claims.forEach((name, value) -> {
                if (value instanceof Boolean b) {
                    out.put(name, b);
                } else if (value instanceof String text) {
                    out.put(name, text);
                } else {
                    throw new IllegalArgumentException("A released claim is a string or a boolean");
                }
            });
        }
        verify.put("loa", levelOfAssurance);
        return toJson(node);
    }

    /**
     * The verification stored in a verify record ({@link #writeVerify}).
     *
     * @throws WalletVerificationException {@code INVALID_RESPONSE} when {@code json} is not exactly a verify record
     */
    public static Verification readVerify(final String json) {
        final JsonNode node = parse(json);
        if (!node.has(VERIFY) || node.has(LINK) || node.has("decision") || node.has("externalSubject")
                || node.has("email") || node.has("levelOfAssurance") || node.get("attributes").size() != 0) {
            throw invalid();
        }
        final JsonNode verify = node.get(VERIFY);
        if (!verify.isObject()) {
            throw invalid();
        }
        onlyMembers(verify, Set.of(NUMBER, TUPLE, "claims", "loa"));
        if (!verify.path("claims").isObject()) {
            throw invalid();
        }
        final Map<String, Object> claims = new LinkedHashMap<>();
        for (final Iterator<Map.Entry<String, JsonNode>> it = verify.get("claims").fields(); it.hasNext(); ) {
            final Map.Entry<String, JsonNode> entry = it.next();
            if (entry.getValue().isBoolean()) {
                claims.put(entry.getKey(), entry.getValue().asBoolean());
            } else if (entry.getValue().isTextual()) {
                claims.put(entry.getKey(), entry.getValue().asText());
            } else {
                throw invalid();
            }
        }
        return new Verification(verify.has(NUMBER) ? text(verify, NUMBER) : null,
                verify.has(TUPLE) ? text(verify, TUPLE) : null, Collections.unmodifiableMap(claims),
                text(verify, "loa"), node.has("format") ? text(node, "format") : null,
                node.has("issuerDn") ? text(node, "issuerDn") : null);
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
        if (node.has(LINK) || node.has(VERIFY)) {
            throw invalid();
        }
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
        if (!node.has("decision") || node.has(LINK) || node.has(VERIFY)) {
            throw invalid();
        }
        final WalletLinkService.Decision decision = decision(node.get("decision"));
        final String format = node.has("format") ? text(node, "format") : null;
        final String issuerDn = node.has("issuerDn") ? text(node, "issuerDn") : null;
        if (decision instanceof WalletLinkService.Decision.Refused) {
            if (node.has("externalSubject") || node.has("email") || node.has("levelOfAssurance")
                    || node.get("attributes").size() != 0) {
                throw invalid();
            }
            return new StoredLogin(null, decision, format, issuerDn, null);
        }
        return new StoredLogin(identity(idpAlias, node), decision, format, issuerDn, null);
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
                || node.has("levelOfAssurance") && !node.get("levelOfAssurance").isTextual()
                || node.has("format") && !node.get("format").isTextual()
                || node.has("issuerDn") && !node.get("issuerDn").isTextual()) {
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
