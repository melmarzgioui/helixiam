/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet.web;

import io.helixiam.authorization.federation.IdentityProviderRegistry;
import io.helixiam.authorization.federation.wallet.AuthorizationRequestFactory;
import io.helixiam.authorization.federation.wallet.WalletIdentityProvider;
import io.helixiam.authorization.federation.wallet.WalletSubject;
import io.helixiam.authorization.federation.wallet.transaction.WalletTransaction;
import io.helixiam.authorization.security.flow.BrowserBinding;
import io.helixiam.common.log.LogSafe;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.util.UriUtils;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;

/**
 * Task 18: the browser side of a wallet login, under {@code /realms/<realm>/broker/<alias>/wallet} (the broker's
 * {@code start} sends the browser here with {@code ?tx=}):
 *
 * <ul>
 *   <li>{@code GET /wallet?tx=}: the themed wallet page ({@code flow/wallet}). While the transaction is fresh: the QR
 *       code of the <b>cross-device</b> invocation URL (server-side SVG, {@link QrCodeSvg}) and an "Open wallet" link
 *       with the <b>same-device</b> URL; {@code /js/wallet-poll.js} then polls the status. A failed login offers a
 *       retry; an expired or unknown one (or one of another browser or realm) is a 404 page that says so.</li>
 *   <li>{@code GET /wallet/status?tx=}: {@code {"status": "PENDING" | "COMPLETED" | "FAILED", "next"?}}, never cached.
 *       {@code PENDING} covers created, request fetched and response received; {@code COMPLETED} covers verified and
 *       redeemed (the store's {@code VERIFIED}); {@code FAILED} is a refused or wallet-declined login. On the first
 *       poll after a CROSS_DEVICE transaction was verified, {@code next} is the broker callback with a fresh response
 *       code ({@code WalletTransactionStore#issueResponseCode}, once: a later poll has no {@code next}). A same-device
 *       login's code went to the wallet's {@code redirect_uri}, so its poll never has a {@code next}.</li>
 *   <li>{@code GET /wallet/unavailable}: the store is full (the provider's {@code start} sends the browser here),
 *       a friendly 503.</li>
 *   <li>{@code GET /wallet/link?reason=}: the wallet was verified but resolves to no account: how to link it.</li>
 * </ul>
 * Status and page belong to the browser that started the login: the session's {@link BrowserBinding} must hash to the
 * transaction's {@code browserBindingHash} (compared in constant time), and the transaction must be of this realm and
 * provider; otherwise a bare 404, the same as for an expired or unknown transaction.
 */
@Controller
public class WalletPageController {

    static final String VIEW = "flow/wallet";
    private static final Logger LOG = LogManager.getLogger(WalletPageController.class);

    private final IdentityProviderRegistry registry;
    private final String idpBaseUrl;
    private final AuthorizationRequestFactory requests = new AuthorizationRequestFactory();

    public WalletPageController(final IdentityProviderRegistry registry,
                                @Value("${idp.base.url}") final String idpBaseUrl) {
        this.registry = registry;
        this.idpBaseUrl = idpBaseUrl;
    }

    /** The client-facing status names (see the class comment). */
    enum ClientStatus { PENDING, COMPLETED, FAILED }

    @GetMapping("/broker/{alias}/wallet")
    public String page(@PathVariable final String alias, @RequestParam(name = "tx", required = false) final String txId,
                       final HttpServletRequest request, final HttpServletResponse response, final Model model) {
        model.addAttribute("alias", alias);
        final Optional<Bound> bound = bound(alias, txId, request);
        if (bound.isEmpty()) {
            response.setStatus(HttpServletResponse.SC_NOT_FOUND);
            model.addAttribute("walletState", "unknown");
            return VIEW;
        }
        final WalletIdentityProvider provider = bound.get().provider();
        final WalletTransaction tx = bound.get().tx();
        model.addAttribute("providerName", provider.metadata().displayName());
        model.addAttribute("statusUrl", request.getContextPath() + "/broker/" + segment(alias) + "/wallet/status?tx="
                + UriUtils.encodeQueryParam(tx.transactionId(), StandardCharsets.UTF_8));
        model.addAttribute("expiresAt", tx.expiresAt().toEpochMilli());
        switch (status(tx)) {
            case FAILED -> model.addAttribute("walletState", "failed");
            case COMPLETED -> model.addAttribute("walletState", "pending");
            case PENDING -> {
                if (tx.status() == WalletTransaction.Status.CREATED) {
                    final String crossDevice = requests.invocationUrl(tx, provider.config(), provider.signingKey(),
                            WalletTransaction.Flow.CROSS_DEVICE, idpBaseUrl);
                    model.addAttribute("walletState", "active");
                    model.addAttribute("qrCode", QrCodeSvg.dataUri(crossDevice));
                    model.addAttribute("sameDeviceUrl", requests.invocationUrl(tx, provider.config(),
                            provider.signingKey(), WalletTransaction.Flow.SAME_DEVICE, idpBaseUrl));
                } else {
                    model.addAttribute("walletState", "pending"); // the wallet has it; keep polling
                }
            }
        }
        return VIEW;
    }

    @GetMapping(value = "/broker/{alias}/wallet/status", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Map<String, Object>> status(@PathVariable final String alias,
                                                      @RequestParam(name = "tx", required = false) final String txId,
                                                      final HttpServletRequest request) {
        final Optional<Bound> bound = bound(alias, txId, request);
        if (bound.isEmpty()) {
            return json(HttpStatus.NOT_FOUND, Map.of());
        }
        final WalletTransaction tx = bound.get().tx();
        final ClientStatus status = status(tx);
        final Map<String, Object> body = new LinkedHashMap<>();
        body.put("status", status.name());
        if (status == ClientStatus.COMPLETED && tx.status() == WalletTransaction.Status.VERIFIED
                && tx.flow() == WalletTransaction.Flow.CROSS_DEVICE) {
            bound.get().provider().transactions().issueResponseCode(tx.transactionId(), bound.get().binding())
                    .ifPresent(code -> {
                        body.put("next", request.getContextPath() + "/broker/" + segment(alias) + "/callback?"
                                + WalletIdentityProvider.RESPONSE_CODE_PARAM + "=" + code + "&state="
                                + UriUtils.encodeQueryParam(tx.helixState(), StandardCharsets.UTF_8));
                        LOG.info("Wallet response code issued to the bound browser: alias={} tx={}",
                                LogSafe.sanitize(alias), tx.transactionId());
                    });
        }
        return json(HttpStatus.OK, body);
    }

    @GetMapping("/broker/{alias}/wallet/unavailable")
    public String unavailable(@PathVariable final String alias, final HttpServletResponse response, final Model model) {
        response.setStatus(HttpServletResponse.SC_SERVICE_UNAVAILABLE);
        model.addAttribute("alias", alias);
        model.addAttribute("walletState", "unavailable");
        return VIEW;
    }

    @GetMapping("/broker/{alias}/wallet/link")
    public String link(@PathVariable final String alias,
                       @RequestParam(name = "reason", required = false) final String reason, final Model model) {
        model.addAttribute("alias", alias);
        model.addAttribute("walletState", "link");
        // Only a known reason is shown (the value comes from the URL).
        model.addAttribute("linkReason", Arrays.stream(WalletSubject.Reason.values())
                .map(r -> r.name().toLowerCase(Locale.ROOT)).filter(r -> r.equals(reason)).findFirst()
                .orElse("link_required"));
        return VIEW;
    }

    /** The provider and transaction, if the transaction is live, of this realm and provider, and this browser's. */
    private Optional<Bound> bound(final String alias, final String txId, final HttpServletRequest request) {
        if (txId == null || txId.isBlank()) {
            return Optional.empty();
        }
        final Optional<WalletIdentityProvider> provider = WalletEndpoints.provider(registry, alias);
        if (provider.isEmpty()) {
            return Optional.empty();
        }
        final WalletTransaction tx = provider.get().transactions().byTransactionId(txId).orElse(null);
        if (!WalletEndpoints.ownedHere(tx, provider.get())) {
            return Optional.empty();
        }
        final HttpSession session = request.getSession(false);
        final String binding = BrowserBinding.current(session, alias);
        if (binding == null || tx.browserBindingHash() == null || !MessageDigest.isEqual(
                binding.getBytes(StandardCharsets.US_ASCII), tx.browserBindingHash().getBytes(StandardCharsets.US_ASCII))) {
            return Optional.empty();
        }
        return Optional.of(new Bound(provider.get(), tx, binding));
    }

    private static ClientStatus status(final WalletTransaction tx) {
        return switch (tx.status()) {
            case VERIFIED, REDEEMED -> ClientStatus.COMPLETED;
            case FAILED, EXPIRED -> ClientStatus.FAILED;
            case CREATED, REQUEST_FETCHED, RESPONSE_RECEIVED -> ClientStatus.PENDING;
        };
    }

    private static String segment(final String value) {
        return UriUtils.encodePathSegment(value, StandardCharsets.UTF_8);
    }

    private static ResponseEntity<Map<String, Object>> json(final HttpStatus status, final Map<String, Object> body) {
        return ResponseEntity.status(status).cacheControl(CacheControl.noStore())
                .contentType(MediaType.APPLICATION_JSON).body(body);
    }

    private record Bound(WalletIdentityProvider provider, WalletTransaction tx, String binding) {
    }
}
