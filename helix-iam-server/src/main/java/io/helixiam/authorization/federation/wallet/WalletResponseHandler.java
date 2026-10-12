/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.ECKey;
import io.helixiam.authorization.federation.AccountLinkingPolicy;
import io.helixiam.authorization.federation.spi.BrokeredIdentity;
import io.helixiam.authorization.federation.wallet.dcql.MatchedPresentations;
import io.helixiam.authorization.federation.wallet.transaction.WalletTransaction;
import io.helixiam.authorization.federation.wallet.transaction.WalletTransactionStore;
import io.helixiam.authorization.security.audit.AuditLog;
import io.helixiam.common.log.LogSafe;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriUtils;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.text.ParseException;
import java.util.Base64;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Task 18: the response endpoint's work (OpenID4VP §8.2/§8.3, docs/eudi-wallet-spec-notes.md §1.5–§1.8, §1.11). It runs
 * on the wallet's POST, which carries no user session; the transaction is found by its {@code responseId} alone.
 *
 * <ol>
 *   <li>The form is checked first, before the transaction is touched: no parameter may repeat, and exactly one of
 *       {@code response} ({@code direct_post.jwt}), {@code vp_token} (dev-only {@code direct_post}) or {@code error}
 *       is present. After the claim it must match the provider's response mode ({@code error} is accepted unencrypted
 *       in either mode, §8.3.1).</li>
 *   <li>{@link WalletTransactionStore#claimResponse} (single use: a second POST is {@code REPLAY}). A transaction of
 *       another realm or provider is failed and answered as not found.</li>
 *   <li>The response: decrypted with the transaction's own ephemeral key and the advertised {@code enc} set
 *       ({@link AuthorizationRequestFactory#RESPONSE_ENC_VALUES}), or, in dev, {@code vp_token} parsed with
 *       {@link StrictJson} (duplicate members refused). A wallet error ({@code error=...}, or an encrypted error) fails
 *       the transaction with {@link WalletErrorCode#WALLET_ERROR} and is acknowledged ({@link Result.WalletErrorRecorded},
 *       §8.2: a processed error response is a 200).</li>
 *   <li>{@code state} must be {@link AuthorizationRequestFactory#walletState} of the transaction.</li>
 *   <li>{@code DcqlResultMatcher} with the provider's verifiers and a {@link VerificationContext} from the provider
 *       (nonce, client_id, response_uri, the mdoc SessionTranscript's JWK thumbprint, anchors, status policy, limits,
 *       clock); then {@link WalletAttributeMapper} (minimum LoA) and {@link WalletSubjectResolver} +
 *       {@link WalletLinkService#decide} (pure). Task 21b: a LINK transaction (account console) skips the decision and
 *       stores only the resolved subject ({@link VerifiedIdentityJson#writeLink}): no login, no JIT.</li>
 *   <li>The identity, the decision and any {@link WalletLinkService.PendingLink} are stored
 *       ({@link VerifiedIdentityJson#write(BrokeredIdentity, WalletLinkService.Decision)}; a refusal stores no
 *       identity) and the transaction completes: same-device with a fresh 128-bit response code returned to the wallet
 *       in the {@code redirect_uri} (the browser callback with only {@code response_code}; the broker's state never reaches
 *       the wallet), cross-device without one
 *       (the bound browser gets it from the status endpoint).</li>
 * </ol>
 * Any failure after the claim fails the transaction with its {@link WalletErrorCode}; the wallet only ever sees the
 * spec code {@code invalid_request}. Never stored or logged: the {@code vp_token}, claim values, nonces, codes, keys.
 */
@Component
public class WalletResponseHandler {

    private static final Logger LOG = LogManager.getLogger(WalletResponseHandler.class);
    private static final int CODE_BYTES = 16;
    private static final Set<String> SINGLE_VALUED = Set.of("response", "vp_token", "state", "error",
            "error_description", "error_uri");

    private final WalletSubjectResolver subjects;
    private final WalletLinkService links;
    private final AccountLinkingPolicy policy;
    private final String idpBaseUrl;
    private final AuditLog audit;
    private final SecureRandom random = new SecureRandom();

    public WalletResponseHandler(final WalletSubjectResolver subjects, final WalletLinkService links,
                                 final AccountLinkingPolicy policy, @Value("${idp.base.url}") final String idpBaseUrl,
                                 final AuditLog audit) {
        this.subjects = subjects;
        this.links = links;
        this.policy = policy;
        this.idpBaseUrl = idpBaseUrl;
        this.audit = audit;
    }

    /** What the response endpoint answers. */
    public sealed interface Result {

        /** Verified: {@code 200 {"redirect_uri": ...}} for same-device, {@code 200 {}} ({@code redirectUri} null). */
        record Accepted(String redirectUri) implements Result {
        }

        /** The wallet's error response was processed: {@code 200 {}}. */
        record WalletErrorRecorded() implements Result {
        }

        /** Refused: {@code 400 {"error": "invalid_request"}}; {@code code} is for the log and tests only. */
        record Rejected(WalletErrorCode code) implements Result {
        }

        /** Not this realm's or this provider's transaction: 404. */
        record NotFound() implements Result {
        }
    }

    /**
     * Handles the wallet's POST to {@code <realm>/oid4vp/<alias>/response/<responseId>}.
     *
     * @param provider the provider the path's alias names (already checked to serve {@code realmId})
     * @param form     the form parameters (each name to all its values)
     */
    public Result handle(final WalletIdentityProvider provider, final String realmId, final String responseId,
                         final Map<String, String[]> form) {
        final String alias = provider.config().alias();
        final Form parsed = Form.of(form);
        if (parsed == null) {
            LOG.warn("Wallet response refused before claim: alias={} realm={} reason={}", LogSafe.sanitize(alias),
                    LogSafe.sanitize(realmId), WalletErrorCode.INVALID_RESPONSE.reason());
            return new Result.Rejected(WalletErrorCode.INVALID_RESPONSE);
        }
        final WalletTransactionStore store = provider.transactions();
        final WalletTransaction tx = store.claimResponse(responseId).orElse(null);
        if (tx == null) {
            LOG.warn("Wallet response refused: alias={} realm={} reason={}", LogSafe.sanitize(alias),
                    LogSafe.sanitize(realmId), WalletErrorCode.REPLAY.reason());
            // Task 22: no transaction to name (already claimed/consumed by the first POST, or never existed).
            audit.emit(WalletLoginAudit.failure(realmId, null, alias, null, null, WalletErrorCode.REPLAY));
            return new Result.Rejected(WalletErrorCode.REPLAY);
        }
        if (!Objects.equals(tx.realmId(), realmId) || !Objects.equals(tx.providerAlias(), alias)) {
            store.fail(tx.transactionId(), WalletErrorCode.INVALID_RESPONSE);
            LOG.warn("Wallet response for another realm or provider: alias={} realm={} tx={}", LogSafe.sanitize(alias),
                    LogSafe.sanitize(realmId), tx.transactionId());
            return new Result.NotFound();
        }
        try {
            return verify(provider, tx, parsed);
        } catch (final WalletVerificationException e) {
            store.fail(tx.transactionId(), e.code());
            audit.emit(WalletLoginAudit.failure(realmId, tx.transactionId(), alias, e.format(), e.issuerDn(),
                    e.code()));
            if (e.code() == WalletErrorCode.WALLET_ERROR || e.code() == WalletErrorCode.WALLET_ACCESS_DENIED) {
                LOG.info("Wallet answered with an error: alias={} realm={} tx={}", LogSafe.sanitize(alias),
                        LogSafe.sanitize(realmId), tx.transactionId());
                return new Result.WalletErrorRecorded();
            }
            LOG.warn("Wallet response refused: alias={} realm={} tx={} reason={} detail={}", LogSafe.sanitize(alias),
                    LogSafe.sanitize(realmId), tx.transactionId(), e.code().reason(), LogSafe.sanitize(e.getMessage()));
            return new Result.Rejected(e.code());
        } catch (final RuntimeException e) {
            // Our side failed (pepper, query, store): never a login, never detail for the wallet.
            store.fail(tx.transactionId(), WalletErrorCode.INVALID_RESPONSE);
            audit.emit(WalletLoginAudit.failure(realmId, tx.transactionId(), alias, null, null,
                    WalletErrorCode.INVALID_RESPONSE));
            LOG.error("Wallet response could not be processed: alias={} realm={} tx={} error={}",
                    LogSafe.sanitize(alias), LogSafe.sanitize(realmId), tx.transactionId(), e.getClass().getSimpleName());
            return new Result.Rejected(WalletErrorCode.INVALID_RESPONSE);
        }
    }

    private Result verify(final WalletIdentityProvider provider, final WalletTransaction tx, final Form form) {
        final WalletProviderConfig config = provider.config();
        final String expectedState = AuthorizationRequestFactory.walletState(tx.transactionId());
        if (form.error() != null) {
            requireState(form.state(), expectedState);
            // §15: "wallet access_denied" gets its own code, distinct from any other wallet-reported error.
            final WalletErrorCode code = "access_denied".equals(form.error()) ? WalletErrorCode.WALLET_ACCESS_DENIED
                    : WalletErrorCode.WALLET_ERROR;
            throw new WalletVerificationException(code, "wallet returned an error response");
        }
        if (!form.fitsMode(config.responseMode())) {
            throw new WalletVerificationException(WalletErrorCode.INVALID_RESPONSE,
                    "the response does not use the requested response mode");
        }
        final boolean encrypted = config.responseMode() == WalletProviderConfig.ResponseMode.DIRECT_POST_JWT;
        final ECKey key = encryptionKey(tx);
        final DecryptedResponse response = encrypted
                ? provider.decryptor().decrypt(form.response(), key, AuthorizationRequestFactory.RESPONSE_ENC_VALUES)
                : new DecryptedResponse(strictObject(form.vpToken()), form.state());
        requireState(response.state(), expectedState);

        final String responseUri = AuthorizationRequestFactory.responseUri(idpBaseUrl, tx);
        final VerificationContext context = provider.verificationContext(tx, responseUri,
                encrypted ? thumbprint(key) : null);
        final MatchedPresentations matched = provider.matcher().match(response.vpToken(), query(tx),
                provider.verifiers(), context);
        final BrokeredIdentity mapped = WalletAttributeMapper.map(config.alias(), null, matched, config.minimumLoa());
        final WalletSubject subject = subjects.resolve(tx.realmId(), matched, config);
        // Task 22: the primary (and, per the default DCQL credential_sets, only) matched presentation's format and
        // issuer DN — public certificate data, never a PID value — kept for the login's audit event.
        final VerifiedPresentation primary = matched.presentations().isEmpty() ? null
                : matched.presentations().get(0);
        final String format = primary == null ? null : primary.format();
        final String issuerDn = primary == null ? null : primary.issuerSubjectDn();
        final String identityJson;
        final String outcome;
        if (tx.purpose() == WalletTransaction.Purpose.LINK) {
            // Task 21b: a link from the account console. Only the resolved subject is kept; no login decision, no JIT:
            // the console's callback links it to the user who started it, and nobody is signed in.
            identityJson = VerifiedIdentityJson.writeLink(subject);
            outcome = "link:" + subject.getClass().getSimpleName();
        } else {
            final WalletLinkService.Decision decision = links.decide(tx.realmId(), config.alias(), subject, policy);
            identityJson = decision instanceof WalletLinkService.Decision.Refused
                    ? VerifiedIdentityJson.write(null, decision, format, issuerDn)
                    : VerifiedIdentityJson.write(new BrokeredIdentity(config.alias(), subjectValue(subject), null,
                            false, mapped.attributes(), mapped.levelOfAssurance()), decision, format, issuerDn);
            outcome = decision.getClass().getSimpleName();
        }

        final boolean sameDevice = tx.flow() == WalletTransaction.Flow.SAME_DEVICE;
        final String code = sameDevice ? token() : null;
        if (!provider.transactions().complete(tx.transactionId(), code, identityJson)) {
            throw new WalletVerificationException(WalletErrorCode.TRANSACTION_EXPIRED,
                    "the transaction expired before it could complete");
        }
        LOG.info("Wallet presentation verified: alias={} realm={} tx={} flow={} formats={} decision={}",
                LogSafe.sanitize(config.alias()), LogSafe.sanitize(tx.realmId()), tx.transactionId(), tx.flow(),
                matched.presentations().stream().map(VerifiedPresentation::format).toList(), outcome);
        return new Result.Accepted(sameDevice ? callback(tx, code) : null);
    }

    /**
     * The browser callback for a same-device login: {@code <base>/realms/<realm>/broker/<alias>/callback?response_code=}
     * only (Task 21b: a link's goes to the account console, {@link WalletIdentityProvider#callbackPath}). The broker's
     * state never goes to the wallet (it is the browser's anti-forgery value); the callback takes the expected state
     * from the browser's session.
     */
    private String callback(final WalletTransaction tx, final String code) {
        String base = idpBaseUrl.trim();
        while (base.endsWith("/")) {
            base = base.substring(0, base.length() - 1);
        }
        return base + "/realms/" + UriUtils.encodePathSegment(tx.realmId(), StandardCharsets.UTF_8)
                + WalletIdentityProvider.callbackPath(tx) + "?" + WalletIdentityProvider.RESPONSE_CODE_PARAM + "="
                + code;
    }

    private static void requireState(final String state, final String expected) {
        if (state == null || !MessageDigest.isEqual(state.getBytes(StandardCharsets.UTF_8),
                expected.getBytes(StandardCharsets.UTF_8))) {
            throw new WalletVerificationException(WalletErrorCode.STATE_MISMATCH,
                    "state is missing or not this transaction's");
        }
    }

    private static ECKey encryptionKey(final WalletTransaction tx) {
        if (tx.encryptionJwkJson() == null) {
            throw new IllegalStateException("The wallet transaction has no response key");
        }
        try {
            return ECKey.parse(tx.encryptionJwkJson());
        } catch (final ParseException e) {
            throw new IllegalStateException("The wallet transaction's response key is unreadable");
        }
    }

    /** RFC 7638 SHA-256 thumbprint of the public key the request advertised (the mdoc handover input, B.2.6.1). */
    private static byte[] thumbprint(final ECKey key) {
        try {
            return key.toPublicJWK().computeThumbprint("SHA-256").decode();
        } catch (final JOSEException e) {
            throw new IllegalStateException("Could not compute the response key thumbprint", e);
        }
    }

    private static JsonNode strictObject(final String vpToken) {
        try {
            final JsonNode node = StrictJson.MAPPER.readTree(vpToken);
            if (node == null || !node.isObject()) {
                throw new WalletVerificationException(WalletErrorCode.INVALID_RESPONSE, "vp_token is not a JSON object");
            }
            return node;
        } catch (final JsonProcessingException e) {
            throw new WalletVerificationException(WalletErrorCode.INVALID_RESPONSE, "vp_token is not strict JSON");
        }
    }

    private static ObjectNode query(final WalletTransaction tx) {
        try {
            return (ObjectNode) StrictJson.MAPPER.readTree(tx.dcqlQueryJson());
        } catch (final JsonProcessingException | ClassCastException e) {
            throw new IllegalStateException("The wallet transaction's DCQL query is unreadable");
        }
    }

    private static String subjectValue(final WalletSubject subject) {
        return switch (subject) {
            case WalletSubject.AdminNumber number -> number.value();
            case WalletSubject.Tuple tuple -> tuple.value();
            case WalletSubject.Unavailable unavailable -> throw new IllegalStateException("No subject to store");
        };
    }

    private String token() {
        final byte[] bytes = new byte[CODE_BYTES];
        random.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    /** The wallet's form, each parameter at most once. */
    private record Form(String response, String vpToken, String state, String error) {

        /** {@code null} when a parameter repeats or not exactly one of response / vp_token / error is present. */
        static Form of(final Map<String, String[]> form) {
            if (form == null) {
                return null;
            }
            for (final Map.Entry<String, String[]> entry : form.entrySet()) {
                if (SINGLE_VALUED.contains(entry.getKey()) && entry.getValue() != null && entry.getValue().length > 1) {
                    return null;
                }
            }
            final Form parsed = new Form(one(form, "response"), one(form, "vp_token"), one(form, "state"),
                    one(form, "error"));
            final int kinds = (parsed.response() != null ? 1 : 0) + (parsed.vpToken() != null ? 1 : 0)
                    + (parsed.error() != null ? 1 : 0);
            return kinds == 1 ? parsed : null;
        }

        /** An error is accepted in either mode; a presentation only in the shape the provider asked for. */
        boolean fitsMode(final WalletProviderConfig.ResponseMode mode) {
            if (error != null) {
                return true;
            }
            return mode == WalletProviderConfig.ResponseMode.DIRECT_POST_JWT ? response != null : vpToken != null;
        }

        private static String one(final Map<String, String[]> form, final String name) {
            final String[] values = form.get(name);
            return values == null || values.length == 0 || values[0] == null || values[0].isEmpty() ? null
                    : values[0];
        }
    }
}
