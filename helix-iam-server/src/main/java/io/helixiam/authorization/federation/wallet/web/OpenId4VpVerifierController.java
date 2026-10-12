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
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;
import java.util.regex.Pattern;

/**
 * Task 18: the OpenID4VP verifier endpoints the wallet calls (no user session; permitted and CSRF-exempt, behind the
 * wallet rate limit and the 256 KB body limit). Under {@code /realms/<realm>} ({@code RealmRoutingFilter} strips it):
 *
 * <ul>
 *   <li>{@code GET|POST /oid4vp/<alias>/request/<requestId>}: the signed request object
 *       ({@code application/oauth-authz-req+jwt}, {@code Cache-Control: no-store}), served once:
 *       {@code claimRequest} records which of the two request ids (same-device or cross-device) was used; a second
 *       fetch of either is 404. POST is the {@code request_uri_method=post} fetch (§5.10): its optional
 *       {@code wallet_nonce} (URL-safe ASCII, at most 256 characters) is echoed in the request object as §5.10
 *       requires; {@code wallet_metadata} is ignored (Helix's request does not depend on it). GET is accepted whatever
 *       the configured method ("Wallets not supporting the post method will send a GET request", §5.1).</li>
 *   <li>{@code POST /oid4vp/<alias>/response/<responseId>}: the Authorization Response, handled by
 *       {@link WalletResponseHandler}; {@code 200 {"redirect_uri": ...}} for a verified same-device login,
 *       {@code 200 {}} for cross-device and for a processed wallet error, {@code 400 {"error":"invalid_request"}} for
 *       any refusal (the reason is logged, never returned).</li>
 * </ul>
 * A provider that does not serve this realm, or a transaction of another realm or provider, is 404 (a transaction
 * claimed under the wrong realm is failed). Request ids, response ids, codes and nonces are never logged.
 */
@RestController
@RequestMapping("/oid4vp/{alias}")
public class OpenId4VpVerifierController {

    /** OpenID4VP §5.10.1. */
    static final MediaType REQUEST_OBJECT_TYPE = MediaType.parseMediaType("application/oauth-authz-req+jwt");
    private static final Logger LOG = LogManager.getLogger(OpenId4VpVerifierController.class);
    private static final Pattern WALLET_NONCE = Pattern.compile("[A-Za-z0-9._~-]{1,256}");
    private static final Map<String, Object> INVALID_REQUEST = Map.of("error", "invalid_request");

    private final IdentityProviderRegistry registry;
    private final WalletResponseHandler responses;
    private final String idpBaseUrl;
    private final AuthorizationRequestFactory requests = new AuthorizationRequestFactory();

    public OpenId4VpVerifierController(final IdentityProviderRegistry registry, final WalletResponseHandler responses,
                                       @Value("${idp.base.url}") final String idpBaseUrl) {
        this.registry = registry;
        this.responses = responses;
        this.idpBaseUrl = idpBaseUrl;
    }

    @RequestMapping(value = "/request/{requestId}", method = {RequestMethod.GET, RequestMethod.POST})
    public ResponseEntity<String> requestObject(@PathVariable final String alias,
                                                @PathVariable final String requestId,
                                                final HttpServletRequest request) {
        final WalletIdentityProvider provider = WalletEndpoints.provider(registry, alias).orElse(null);
        if (provider == null) {
            return notFound();
        }
        String walletNonce = null;
        if ("POST".equalsIgnoreCase(request.getMethod())) {
            final String[] nonces = request.getParameterValues("wallet_nonce");
            if (nonces != null && (nonces.length != 1 || !WALLET_NONCE.matcher(nonces[0]).matches())) {
                return ResponseEntity.badRequest().cacheControl(CacheControl.noStore()).body(null);
            }
            walletNonce = nonces == null ? null : nonces[0];
        }
        final WalletTransaction tx = provider.transactions().claimRequest(requestId).orElse(null);
        if (tx == null) {
            return notFound();
        }
        if (!WalletEndpoints.ownedHere(tx, provider)) {
            provider.transactions().fail(tx.transactionId(), WalletErrorCode.INVALID_RESPONSE);
            LOG.warn("Wallet request object asked for under another realm or provider: alias={} realm={} tx={}",
                    LogSafe.sanitize(alias), LogSafe.sanitize(RealmContextHolder.get()), tx.transactionId());
            return notFound();
        }
        final String jwt;
        try {
            jwt = requests.signedRequestObject(tx, provider.config(), provider.signingKey(), idpBaseUrl, walletNonce);
        } catch (final IllegalStateException e) {
            provider.transactions().fail(tx.transactionId(), WalletErrorCode.TRANSACTION_EXPIRED);
            LOG.warn("Wallet request object not issued: alias={} realm={} tx={} reason={}", LogSafe.sanitize(alias),
                    LogSafe.sanitize(tx.realmId()), tx.transactionId(), LogSafe.sanitize(e.getMessage()));
            return notFound();
        }
        LOG.info("Wallet request object served: alias={} realm={} tx={} flow={}", LogSafe.sanitize(alias),
                LogSafe.sanitize(tx.realmId()), tx.transactionId(), tx.flow());
        return ResponseEntity.ok().cacheControl(CacheControl.noStore()).contentType(REQUEST_OBJECT_TYPE).body(jwt);
    }

    @PostMapping("/response/{responseId}")
    public ResponseEntity<Map<String, Object>> response(@PathVariable final String alias,
                                                        @PathVariable final String responseId,
                                                        final HttpServletRequest request) {
        final WalletIdentityProvider provider = WalletEndpoints.provider(registry, alias).orElse(null);
        if (provider == null) {
            return json(HttpStatus.NOT_FOUND, Map.of());
        }
        final WalletResponseHandler.Result result = responses.handle(provider, RealmContextHolder.get(), responseId,
                request.getParameterMap());
        return switch (result) {
            case WalletResponseHandler.Result.Accepted accepted -> json(HttpStatus.OK,
                    accepted.redirectUri() == null ? Map.of() : Map.of("redirect_uri", accepted.redirectUri()));
            case WalletResponseHandler.Result.WalletErrorRecorded recorded -> json(HttpStatus.OK, Map.of());
            case WalletResponseHandler.Result.Rejected rejected -> json(HttpStatus.BAD_REQUEST, INVALID_REQUEST);
            case WalletResponseHandler.Result.NotFound notFound -> json(HttpStatus.NOT_FOUND, Map.of());
        };
    }

    private static ResponseEntity<String> notFound() {
        return ResponseEntity.status(HttpStatus.NOT_FOUND).cacheControl(CacheControl.noStore()).body(null);
    }

    private static ResponseEntity<Map<String, Object>> json(final HttpStatus status, final Map<String, Object> body) {
        return ResponseEntity.status(status).cacheControl(CacheControl.noStore())
                .contentType(MediaType.APPLICATION_JSON).body(body);
    }
}
