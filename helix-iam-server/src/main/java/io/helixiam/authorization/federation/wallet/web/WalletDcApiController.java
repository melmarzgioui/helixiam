/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet.web;

import io.helixiam.authorization.federation.IdentityProviderRegistry;
import io.helixiam.authorization.federation.wallet.AuthorizationRequestFactory;
import io.helixiam.authorization.federation.wallet.WalletErrorCode;
import io.helixiam.authorization.federation.wallet.WalletIdentityProvider;
import io.helixiam.authorization.federation.wallet.WalletResponseHandler;
import io.helixiam.authorization.federation.wallet.transaction.WalletTransaction;
import io.helixiam.authorization.security.flow.BrowserBinding;
import io.helixiam.authorization.security.realm.RealmContextHolder;
import io.helixiam.common.log.LogSafe;
import jakarta.servlet.http.HttpServletRequest;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

/**
 * OpenID4VP over the W3C Digital Credentials API (OpenID4VP 1.0 Appendix A, HAIP 1.0 §5.2): the login page's side,
 * under the wallet page ({@code /realms/<realm>/broker/<alias>/wallet/dc-api/...}). Both are POSTs from the page that
 * started the login: Spring Security's CSRF check applies (these paths are not exempt; the page sends
 * {@code X-XSRF-TOKEN}), and the session's {@link BrowserBinding} must hash to the transaction's binding (constant
 * time), the transaction must be of this realm and provider, and the provider must have the DC API on; otherwise a
 * bare {@code 404}, as for an unknown or expired transaction.
 *
 * <ul>
 *   <li>{@code POST …/wallet/dc-api/request?tx=}: {@code {"protocol": "openid4vp-v1-signed" | "openid4vp-v1-unsigned",
 *       "data": {...}}} for {@code navigator.credentials.get} ({@link AuthorizationRequestFactory#dcApiRequest}), with
 *       the provider's expected origins from configuration ({@code dcApi.expectedOrigins}, else the origin of
 *       {@code idp.base.url}). The transaction is not changed and must still be CREATED (a wallet has not fetched its
 *       QR or same-device request): a user who cancels the browser's credential sheet can still scan the QR code.</li>
 *   <li>{@code POST …/wallet/dc-api/response?tx=} ({@code application/json}, at most
 *       {@code helix.wallet.max-request-bytes}): the {@code DigitalCredential} as {@code {"protocol", "data"}}, handled
 *       by {@link WalletResponseHandler#handleDcApi}. Verified: {@code 200 {"status":"COMPLETED","next":<the broker
 *       callback with a fresh response code>}}; a wallet error: {@code 200 {"status":"FAILED","reason":...}}; refused:
 *       {@code 400 {"status":"FAILED","reason":...}} ({@link WalletFailureClass}: never the specific check); too
 *       large: {@code 413}.</li>
 * </ul>
 */
@RestController
public class WalletDcApiController {

    private static final Logger LOG = LogManager.getLogger(WalletDcApiController.class);
    private static final int CHUNK = 8192;

    private final IdentityProviderRegistry registry;
    private final WalletResponseHandler responses;
    private final String idpBaseUrl;
    private final int maxBytes;
    private final AuthorizationRequestFactory requests = new AuthorizationRequestFactory();

    public WalletDcApiController(final IdentityProviderRegistry registry, final WalletResponseHandler responses,
                                 @Value("${idp.base.url}") final String idpBaseUrl,
                                 @Value("${helix.wallet.max-request-bytes:" + WalletRequestBodyLimitFilter.DEFAULT_MAX_BYTES
                                         + "}") final int maxBytes) {
        this.registry = registry;
        this.responses = responses;
        this.idpBaseUrl = idpBaseUrl;
        this.maxBytes = maxBytes;
    }

    @PostMapping(value = "/broker/{alias}/wallet/dc-api/request", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Map<String, Object>> request(@PathVariable final String alias,
                                                       @RequestParam(name = "tx", required = false) final String txId,
                                                       final HttpServletRequest request) {
        final Bound bound = bound(alias, txId, request).orElse(null);
        if (bound == null || bound.tx().status() != WalletTransaction.Status.CREATED) {
            return json(HttpStatus.NOT_FOUND, Map.of());
        }
        final WalletIdentityProvider provider = bound.provider();
        final AuthorizationRequestFactory.DcApiRequest dcApi;
        try {
            dcApi = requests.dcApiRequest(bound.tx(), provider.config(), provider.signingKey(),
                    provider.config().dcApi().effectiveOrigins(idpBaseUrl));
        } catch (final RuntimeException e) {
            LOG.warn("Wallet DC API request not issued: alias={} realm={} tx={} error={}", LogSafe.sanitize(alias),
                    LogSafe.sanitize(bound.tx().realmId()), bound.tx().transactionId(), e.getClass().getSimpleName());
            return json(HttpStatus.NOT_FOUND, Map.of());
        }
        LOG.info("Wallet DC API request issued: alias={} realm={} tx={} protocol={}", LogSafe.sanitize(alias),
                LogSafe.sanitize(bound.tx().realmId()), bound.tx().transactionId(), dcApi.protocol());
        final Map<String, Object> body = new LinkedHashMap<>();
        body.put("protocol", dcApi.protocol());
        body.put("data", dcApi.data());
        return json(HttpStatus.OK, body);
    }

    @PostMapping(value = "/broker/{alias}/wallet/dc-api/response", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Map<String, Object>> response(@PathVariable final String alias,
                                                        @RequestParam(name = "tx", required = false) final String txId,
                                                        final HttpServletRequest request) throws IOException {
        if (request.getContentLengthLong() > maxBytes) {
            return json(HttpStatus.PAYLOAD_TOO_LARGE, Map.of());
        }
        final Bound bound = bound(alias, txId, request).orElse(null);
        if (bound == null) {
            return json(HttpStatus.NOT_FOUND, Map.of());
        }
        final byte[] raw = readAtMost(request.getInputStream(), maxBytes + 1);
        if (raw.length > maxBytes) {
            return json(HttpStatus.PAYLOAD_TOO_LARGE, Map.of());
        }
        final WalletIdentityProvider provider = bound.provider();
        final WalletTransaction tx = bound.tx();
        final WalletResponseHandler.Result result = responses.handleDcApi(provider, RealmContextHolder.get(), tx,
                new String(raw, StandardCharsets.UTF_8));
        return switch (result) {
            case WalletResponseHandler.Result.Accepted accepted -> {
                final Map<String, Object> body = new LinkedHashMap<>();
                body.put("status", "COMPLETED");
                provider.transactions().issueResponseCode(tx.transactionId(), bound.binding()).ifPresent(code -> {
                    body.put("next", request.getContextPath() + WalletIdentityProvider.callbackPath(tx) + "?"
                            + WalletIdentityProvider.RESPONSE_CODE_PARAM + "=" + code);
                    LOG.info("Wallet response code issued to the bound browser (DC API): alias={} tx={}",
                            LogSafe.sanitize(alias), tx.transactionId());
                });
                yield json(HttpStatus.OK, body);
            }
            case WalletResponseHandler.Result.WalletErrorRecorded recorded -> json(HttpStatus.OK, failed(
                    provider.transactions().byTransactionId(tx.transactionId())
                            .map(WalletTransaction::failureCode).orElse(WalletErrorCode.WALLET_ERROR)));
            case WalletResponseHandler.Result.Rejected rejected -> json(HttpStatus.BAD_REQUEST, failed(rejected.code()));
            case WalletResponseHandler.Result.NotFound notFound -> json(HttpStatus.NOT_FOUND, Map.of());
        };
    }

    private static Map<String, Object> failed(final WalletErrorCode code) {
        return Map.of("status", "FAILED", "reason", WalletFailureClass.of(code).key());
    }

    /** The provider and transaction, if the transaction is live, of this realm and provider, and this browser's. */
    private Optional<Bound> bound(final String alias, final String txId, final HttpServletRequest request) {
        if (txId == null || txId.isBlank()) {
            return Optional.empty();
        }
        final WalletIdentityProvider provider = WalletEndpoints.provider(registry, alias).orElse(null);
        if (provider == null || !provider.config().dcApi().enabled()) {
            return Optional.empty();
        }
        final WalletTransaction tx = provider.transactions().byTransactionId(txId).orElse(null);
        if (!WalletEndpoints.ownedHere(tx, provider) || tx.status() == WalletTransaction.Status.EXPIRED) {
            return Optional.empty();
        }
        final String binding = BrowserBinding.current(request.getSession(false), RealmContextHolder.get(), alias);
        if (binding == null || tx.browserBindingHash() == null || !MessageDigest.isEqual(
                binding.getBytes(StandardCharsets.US_ASCII), tx.browserBindingHash().getBytes(StandardCharsets.US_ASCII))) {
            return Optional.empty();
        }
        return Optional.of(new Bound(provider, tx, binding));
    }

    private static byte[] readAtMost(final InputStream in, final int limit) throws IOException {
        final ByteArrayOutputStream out = new ByteArrayOutputStream();
        final byte[] buffer = new byte[CHUNK];
        while (out.size() < limit) {
            final int n = in.read(buffer, 0, Math.min(buffer.length, limit - out.size()));
            if (n < 0) {
                break;
            }
            out.write(buffer, 0, n);
        }
        return out.toByteArray();
    }

    private static ResponseEntity<Map<String, Object>> json(final HttpStatus status, final Map<String, Object> body) {
        return ResponseEntity.status(status).cacheControl(CacheControl.noStore())
                .contentType(MediaType.APPLICATION_JSON).body(body);
    }

    private record Bound(WalletIdentityProvider provider, WalletTransaction tx, String binding) {
    }
}
