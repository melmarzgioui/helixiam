/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.controller.admin;

import io.helixiam.authorization.amqp.key.RealmKeyConfigPublisher;
import io.helixiam.authorization.amqp.key.RealmKeyView;
import io.helixiam.authorization.security.audit.AuditContext;
import io.helixiam.authorization.service.key.KeyImportException;
import io.helixiam.authorization.service.key.RealmKeyService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Size;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.function.Supplier;

/**
 * Helix IAM B8 + bring-your-own keys: admin REST API for per-realm signing keys — the backend of the console's "Realm
 * keys" screen. The realm always comes from the path; a key id of another realm is 404.
 *
 * <ul>
 *   <li>{@code GET /keys} — every key with its certificate facts (never the private key).</li>
 *   <li>{@code POST /keys/import} {@code {privateKeyPem, certificateChainPem}} — a PENDING key (201).</li>
 *   <li>{@code POST /keys/csr} {@code {algorithm, subject, dnsNames}} — a PENDING key + PKCS#10 CSR (201).</li>
 *   <li>{@code GET /keys/{keyId}/csr} — that CSR again.</li>
 *   <li>{@code PUT /keys/{keyId}/certificate} {@code {certificateChainPem}} — attach a CA-signed chain.</li>
 *   <li>{@code POST /keys/{keyId}/activate} — the PENDING key signs; the previous ACTIVE key becomes ROTATED.</li>
 *   <li>{@code POST /keys/rotate} {@code {algorithm?}} — generate and activate at once.</li>
 *   <li>{@code DELETE /keys/{keyId}} — retire (the ACTIVE key is refused, 409).</li>
 * </ul>
 *
 * Invalid input is {@code 400 {message, fieldErrors}}; a state conflict is {@code 409 {message}}. Every write is
 * audited ({@code REALM_KEY_*}) with keyId, algorithm and fingerprint — never key material.
 */
@RestController
@RequestMapping("/admin/realms/{realmId}/keys")
public class RealmKeyAdminController {

    private static final int MAX_PEM = 65_536;

    private final RealmKeyConfigPublisher publisher;
    private final io.helixiam.authorization.security.adminrbac.AdminAuthorizationManager rbac;

    public RealmKeyAdminController(final RealmKeyConfigPublisher publisher,
                                   final io.helixiam.authorization.security.adminrbac.AdminAuthorizationManager rbac) {
        this.publisher = publisher;
        this.rbac = rbac;
    }

    /**
     * Defence in depth (security review): every key write needs realm-admin, checked here as well, independent of
     * how the route was matched to a permission.
     */
    private ResponseEntity<?> forbiddenUnlessRealmAdmin(final String realmId) {
        final org.springframework.security.core.Authentication auth =
                org.springframework.security.core.context.SecurityContextHolder.getContext().getAuthentication();
        if (rbac.permits(auth, realmId,
                io.helixiam.authorization.security.adminrbac.AdminRoutePermissions.REALM_ADMIN)) {
            return null;
        }
        return ResponseEntity.status(HttpStatus.FORBIDDEN)
                .body(Map.of("error", "forbidden", "message", "Changing realm signing keys needs realm-admin."));
    }

    /** {@code POST /keys/import}. Write-only private key: never echoed, logged or audited. */
    public record ImportRequest(@Size(max = MAX_PEM, message = "The private key is too long") String privateKeyPem,
                                @Size(max = MAX_PEM, message = "The certificate chain is too long")
                                String certificateChainPem) {
        @Override
        public String toString() {
            return "ImportRequest[…]";
        }
    }

    /** {@code POST /keys/csr}. */
    public record CsrRequest(String algorithm,
                             @Size(max = 1024, message = "The subject is too long") String subject,
                             @Size(max = 20, message = "At most 20 DNS names") List<String> dnsNames) {
    }

    /** {@code PUT /keys/{keyId}/certificate}. */
    public record CertificateRequest(@Size(max = MAX_PEM, message = "The certificate chain is too long")
                                     String certificateChainPem) {
    }

    /** {@code POST /keys/rotate} (optional body). */
    public record RotateRequest(String algorithm) {
    }

    /** All keys for the realm (every status), newest first. */
    @GetMapping
    public List<RealmKeyView> list(@PathVariable final String realmId) {
        return publisher.list(realmId);
    }

    @PostMapping("/import")
    public ResponseEntity<?> importKey(@PathVariable final String realmId,
                                       @Valid @RequestBody final ImportRequest request, final HttpServletRequest http) {
        final ResponseEntity<?> denied = forbiddenUnlessRealmAdmin(realmId);
        if (denied != null) {
            return denied;
        }
        return write(http, HttpStatus.CREATED,
                () -> publisher.importKey(realmId, request.privateKeyPem(), request.certificateChainPem()));
    }

    @PostMapping("/csr")
    public ResponseEntity<?> csr(@PathVariable final String realmId, @Valid @RequestBody final CsrRequest request,
                                 final HttpServletRequest http) {
        final ResponseEntity<?> denied = forbiddenUnlessRealmAdmin(realmId);
        if (denied != null) {
            return denied;
        }
        try {
            final RealmKeyConfigPublisher.CsrView result = publisher.createCsr(realmId, request.algorithm(),
                    request.subject(), request.dnsNames());
            audit(http, result.key());
            return ResponseEntity.status(HttpStatus.CREATED).body(result);
        } catch (final KeyImportException e) {
            throw invalid(e);
        }
    }

    @GetMapping(value = "/{keyId}/csr")
    public ResponseEntity<Map<String, String>> downloadCsr(@PathVariable final String realmId,
                                                           @PathVariable final String keyId) {
        return publisher.csr(realmId, keyId).map(csr -> ResponseEntity.ok().contentType(MediaType.APPLICATION_JSON)
                .body(Map.of("csrPem", csr))).orElseGet(() -> ResponseEntity.notFound().build());
    }

    @PutMapping("/{keyId}/certificate")
    public ResponseEntity<?> attachCertificate(@PathVariable final String realmId, @PathVariable final String keyId,
                                               @Valid @RequestBody final CertificateRequest request,
                                               final HttpServletRequest http) {
        final ResponseEntity<?> denied = forbiddenUnlessRealmAdmin(realmId);
        if (denied != null) {
            return denied;
        }
        return write(http, HttpStatus.OK,
                () -> publisher.attachCertificate(realmId, keyId, request.certificateChainPem()));
    }

    @PostMapping("/{keyId}/activate")
    public ResponseEntity<?> activate(@PathVariable final String realmId, @PathVariable final String keyId,
                                      final HttpServletRequest http) {
        final ResponseEntity<?> denied = forbiddenUnlessRealmAdmin(realmId);
        if (denied != null) {
            return denied;
        }
        return write(http, HttpStatus.OK, () -> publisher.activate(realmId, keyId));
    }

    /** Generate a key (RS256 unless {@code algorithm} says ES256) and activate it at once. */
    @PostMapping("/rotate")
    public ResponseEntity<?> rotate(@PathVariable final String realmId,
                                    @RequestBody(required = false) final RotateRequest request,
                                    final HttpServletRequest http) {
        final ResponseEntity<?> denied = forbiddenUnlessRealmAdmin(realmId);
        if (denied != null) {
            return denied;
        }
        return write(http, HttpStatus.OK,
                () -> publisher.rotate(realmId, request == null ? null : request.algorithm()));
    }

    /** Retire a key so it drops out of the JWKS and SAML metadata. 404 unknown here, 409 for the ACTIVE key. */
    @DeleteMapping("/{keyId}")
    public ResponseEntity<?> retire(@PathVariable final String realmId, @PathVariable final String keyId,
                                    final HttpServletRequest http) {
        final ResponseEntity<?> denied = forbiddenUnlessRealmAdmin(realmId);
        if (denied != null) {
            return denied;
        }
        final RealmKeyView before = publisher.list(realmId).stream().filter(k -> keyId.equals(k.keyId()))
                .findFirst().orElse(null);
        return switch (publisher.retire(realmId, keyId)) {
            case NOT_FOUND -> ResponseEntity.notFound().build();
            case ACTIVE_REFUSED -> conflict("The active key cannot be retired; activate or rotate to another key first.");
            case RETIRED -> {
                if (before != null) {
                    audit(http, before);
                }
                yield ResponseEntity.noContent().build();
            }
        };
    }

    private ResponseEntity<?> write(final HttpServletRequest http, final HttpStatus status,
                                    final Supplier<RealmKeyView> action) {
        try {
            final RealmKeyView view = action.get();
            audit(http, view);
            return ResponseEntity.status(status).body(view);
        } catch (final KeyImportException e) {
            throw invalid(e);
        } catch (final NoSuchElementException e) {
            return ResponseEntity.notFound().build();
        } catch (final RealmKeyService.KeyStateException e) {
            return conflict(e.getMessage());
        }
    }

    private static ProviderValidationException invalid(final KeyImportException e) {
        final String message = e.getMessage() == null || e.getMessage().isBlank()
                ? "The key could not be imported." : e.getMessage();
        return new ProviderValidationException(Map.of(e.field(), message));
    }

    private static ResponseEntity<Map<String, String>> conflict(final String message) {
        return ResponseEntity.status(HttpStatus.CONFLICT).body(Map.of("error", "conflict", "message", message));
    }

    /** keyId, algorithm and fingerprint — public facts only. */
    private static void audit(final HttpServletRequest http, final RealmKeyView view) {
        final Map<String, String> detail = new LinkedHashMap<>();
        detail.put("keyId", view.keyId());
        detail.put("algorithm", view.algorithm());
        if (view.fingerprint() != null) {
            detail.put("fingerprint", view.fingerprint());
        }
        if (view.kid() != null) {
            detail.put("kid", view.kid());
        }
        AuditContext.attachDetail(http, detail);
    }
}
