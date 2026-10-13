/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.controller.account;

import io.helixiam.authorization.amqp.account.AccountIdentityPublisher;
import io.helixiam.authorization.amqp.account.AccountUnlinkRef;
import io.helixiam.authorization.amqp.account.FederatedLinkDto;
import io.helixiam.authorization.domain.UserCredentials;
import io.helixiam.authorization.federation.IdentityProviderRegistry;
import io.helixiam.authorization.security.realm.RealmContextHolder;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

/**
 * Helix IAM B9: the end-user account console's "Connected accounts" — the signed-in user views the
 * identity providers their account is linked through (Google, DigiD, …) and disconnects any of them.
 * Like the rest of {@code /account/**}, every operation is pinned to the authenticated principal's userId,
 * so a user can only ever see and unlink <em>their own</em> federated logins.
 *
 * <p>Task 21b fix round 1: EU Digital Identity Wallet links are a security setting managed only in the account
 * console's wallet section (step-up, audit, every link of the provider removed). This API leaves wallet providers out
 * of the list (their subjects are HMAC hashes) and answers a delete of a wallet alias with 409 and changes nothing.
 * Every other provider behaves as before.
 */
@RestController
@RequestMapping("/account/identities")
public class AccountIdentityController {

    static final String WALLET_MESSAGE = "Wallet links are managed in the account console's wallet section.";

    private final AccountIdentityPublisher publisher;
    private final IdentityProviderRegistry registry;

    public AccountIdentityController(final AccountIdentityPublisher publisher,
                                     final IdentityProviderRegistry registry) {
        this.publisher = publisher;
        this.registry = registry;
    }

    /** The caller's connected federated identities. 401 when unauthenticated. */
    @GetMapping
    public ResponseEntity<List<FederatedLinkDto>> list(@AuthenticationPrincipal final UserCredentials principal) {
        if (principal == null || principal.getUserId() == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
        final List<FederatedLinkDto> links = publisher.list(principal.getUserId());
        return ResponseEntity.ok(links == null ? List.of()
                : links.stream().filter(link -> !isWallet(link.idpAlias())).toList());
    }

    /** Disconnect one provider for the caller; 404 when they had no such link. */
    @DeleteMapping("/{alias}")
    public ResponseEntity<?> unlink(@AuthenticationPrincipal final UserCredentials principal,
                                    @PathVariable final String alias) {
        if (principal == null || principal.getUserId() == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
        if (isWallet(alias)) {
            return ResponseEntity.status(HttpStatus.CONFLICT).body(Map.of("message", WALLET_MESSAGE));
        }
        final boolean removed = Boolean.TRUE.equals(
                publisher.unlink(new AccountUnlinkRef(principal.getUserId(), alias)));
        return removed ? ResponseEntity.noContent().build() : ResponseEntity.notFound().build();
    }

    /**
     * Whether {@code alias} names an EU Digital Identity Wallet provider. Production readiness item 5: resolved in the
     * caller's own realm first ({@link IdentityProviderRegistry#isWallet}), so another realm's wallet that happens to
     * share the alias of this realm's OIDC connection never hides or locks the user's OIDC link; only an alias this
     * realm does not serve falls back to every realm's providers (links are per user).
     */
    private boolean isWallet(final String alias) {
        return registry.isWallet(RealmContextHolder.get(), alias);
    }
}
