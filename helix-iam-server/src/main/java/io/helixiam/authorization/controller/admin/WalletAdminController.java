/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.controller.admin;

import io.helixiam.authorization.federation.wallet.WalletProviderConfig;
import io.helixiam.authorization.federation.wallet.dcql.DcqlQueryBuilder;
import io.helixiam.authorization.service.key.SoftwareRealmSigningKeys;
import io.helixiam.common.startup.DeploymentProfile;
import jakarta.validation.Valid;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Task 24: read-only helpers behind the console's "EUDI Wallet (OpenID4VP)" provider form, so the console never
 * duplicates server rules: {@code GET .../wallet/metadata} (the PID claim catalogue of {@link DcqlQueryBuilder}, the
 * defaults, and whether the dev profile is active, which decides whether {@code direct_post} is offered) and
 * {@code POST .../wallet/certificates/preview} (a PEM bundle parsed into each certificate's public facts, with the
 * reason a certificate cannot be a trust anchor). Nothing is stored. Access needs {@code manage-identity-providers}
 * ({@code AdminRoutePermissions}, group {@code wallet}).
 */
@RestController
@RequestMapping("/admin/realms/{realmId}/wallet")
public class WalletAdminController {

    /** A preview shows at most this many certificates; a trust-anchor bundle is a handful. */
    static final int MAX_PREVIEW_CERTIFICATES = 50;

    private final DeploymentProfile profile;

    public WalletAdminController(final DeploymentProfile profile) {
        this.profile = profile;
    }

    /** One requestable PID claim: its canonical name and whether an mdoc PID carries it. */
    public record PidClaim(String name, boolean mdoc) {
    }

    /** What the console's wallet form needs to know about this server. */
    public record WalletMetadata(List<PidClaim> pidClaims, List<String> defaultRequestedClaims,
                                 List<String> credentialFormats, boolean devProfile) {
    }

    /** The certificates of a previewed bundle, in bundle order. */
    public record CertificatePreview(List<CertificateView> certificates) {
    }

    @GetMapping("/metadata")
    public WalletMetadata metadata(@PathVariable final String realmId) {
        final List<PidClaim> claims = new ArrayList<>();
        DcqlQueryBuilder.pidClaimCatalogue().forEach((name, mdoc) -> claims.add(new PidClaim(name, mdoc)));
        return new WalletMetadata(List.copyOf(claims), WalletProviderConfig.Pid.DEFAULT_REQUESTED_CLAIMS,
                WalletProviderConfig.DEFAULT_FORMATS, profile.isDev());
    }

    @PostMapping("/certificates/preview")
    public CertificatePreview preview(@PathVariable final String realmId,
                                      @Valid @RequestBody final CertificatePreviewRequest request) {
        final List<X509Certificate> certs;
        try {
            certs = SoftwareRealmSigningKeys.parseCertificateChain(request.pem());
        } catch (final IllegalArgumentException e) {
            throw new ProviderValidationException(Map.of("pem",
                    "The text could not be read as PEM certificates (only BEGIN CERTIFICATE blocks)."));
        }
        if (certs.size() > MAX_PREVIEW_CERTIFICATES) {
            throw new ProviderValidationException(Map.of("pem",
                    "A bundle can hold at most " + MAX_PREVIEW_CERTIFICATES + " certificates."));
        }
        return new CertificatePreview(certs.stream().map(CertificateView::of).toList());
    }
}
