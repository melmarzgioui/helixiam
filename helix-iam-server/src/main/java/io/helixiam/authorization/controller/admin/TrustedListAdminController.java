/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.controller.admin;

import io.helixiam.authorization.federation.wallet.trust.TrustAnchors;
import io.helixiam.authorization.federation.wallet.trust.tl.ListedService;
import io.helixiam.authorization.federation.wallet.trust.tl.PemCertificates;
import io.helixiam.authorization.federation.wallet.trust.tl.TrustedListHealth;
import io.helixiam.authorization.federation.wallet.trust.tl.TrustedListService;
import io.helixiam.authorization.federation.wallet.trust.tl.TrustedListSource;
import io.helixiam.authorization.federation.wallet.trust.tl.TrustedListSpec;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.security.auth.x500.X500Principal;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;

/**
 * The realm's trusted list sources for the EUDI wallet (console: Federation → Trusted lists). Each source is a
 * published, signed list (ETSI TS 119 612 XML or ETSI TS 119 602 LoTE JSON) whose verified service certificates
 * become wallet trust anchors for the providers that name it in {@code trustedLists.sources}.
 *
 * <p>Conventions: access needs {@code manage-identity-providers} ({@code AdminRoutePermissions}, group
 * {@code trusted-lists}); writes need the CSRF header; create/update/delete/refresh are audited by the admin audit
 * filter ({@code TRUSTED_LIST_CREATE|UPDATE|DELETE|REFRESH_REQUEST}) and the refresh itself by the service
 * ({@code TRUSTED_LIST_REFRESHED|REFRESH_FAILED}). Bad settings are {@code 400 {message, fieldErrors}}; a refresh
 * while another one holds the source is {@code 409}.
 */
@RestController
@RequestMapping("/admin/realms/{realmId}/trusted-lists")
public class TrustedListAdminController {

    private final TrustedListService service;

    public TrustedListAdminController(final TrustedListService service) {
        this.service = service;
    }

    /** The admin's settings for a source. Lists may be null (empty). */
    public record TrustedListRequest(String name, String url, String format, String signerCertificates,
                                     List<String> serviceTypes, List<String> acceptedStatuses,
                                     List<String> territories, Integer graceHours, Boolean enabled) {
    }

    /** A source as the console shows it; times are ISO-8601 or null. */
    public record TrustedListView(String id, String name, String url, String format, String signerCertificates,
                                  List<CertificateView> signers, List<String> serviceTypes,
                                  List<String> acceptedStatuses, List<String> effectiveStatuses,
                                  List<String> territories, int graceHours, boolean enabled, String status,
                                  boolean anchorsInUse, String lastAttemptAt, String lastSuccessAt,
                                  String listIssuedAt, String nextUpdate, String anchorsUsableUntil,
                                  String nextRefreshAt, Long sequenceNumber, Integer listsRead, String lastError,
                                  int serviceCount, int anchorCount, boolean listOfLists, List<MemberView> members) {
    }

    /** One member of a list of trusted lists, with its own state. */
    public record MemberView(String territory, String location, String status, boolean anchorsInUse,
                             Long sequenceNumber, String listIssuedAt, String nextUpdate, String anchorsUsableUntil,
                             String lastAttemptAt, String lastSuccessAt, String lastError, int serviceCount,
                             int anchorCount) {
    }

    /** One verified service of the last good list. */
    public record TrustedListAnchorView(String subject, String issuer, String serialNumber, String notAfter,
                                        String serviceName, String provider, String country, String serviceType,
                                        String status, boolean usable, String problem) {
    }

    @GetMapping
    public List<TrustedListView> list(@PathVariable final String realmId) {
        return service.list(realmId).stream().map(this::view).toList();
    }

    @GetMapping("/{id}")
    public ResponseEntity<TrustedListView> get(@PathVariable final String realmId, @PathVariable final String id) {
        return service.get(realmId, id).map(this::view).map(ResponseEntity::ok)
                .orElseGet(() -> ResponseEntity.notFound().build());
    }

    @GetMapping("/{id}/anchors")
    public ResponseEntity<List<TrustedListAnchorView>> anchors(@PathVariable final String realmId,
                                                               @PathVariable final String id) {
        return service.get(realmId, id).map(s -> service.services(s).stream().map(TrustedListAdminController::anchor)
                .toList()).map(ResponseEntity::ok).orElseGet(() -> ResponseEntity.notFound().build());
    }

    @PostMapping
    public ResponseEntity<TrustedListView> create(@PathVariable final String realmId,
                                                  @RequestBody final TrustedListRequest request) {
        try {
            return ResponseEntity.status(HttpStatus.CREATED).body(view(service.create(realmId, config(request))));
        } catch (final TrustedListService.InvalidConfigException e) {
            throw new ProviderValidationException(e.fieldErrors());
        }
    }

    @PutMapping("/{id}")
    public ResponseEntity<TrustedListView> update(@PathVariable final String realmId, @PathVariable final String id,
                                                  @RequestBody final TrustedListRequest request) {
        try {
            return service.update(realmId, id, config(request)).map(this::view).map(ResponseEntity::ok)
                    .orElseGet(() -> ResponseEntity.notFound().build());
        } catch (final TrustedListService.InvalidConfigException e) {
            throw new ProviderValidationException(e.fieldErrors());
        }
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> delete(@PathVariable final String realmId, @PathVariable final String id) {
        return service.delete(realmId, id) ? ResponseEntity.noContent().build() : ResponseEntity.notFound().build();
    }

    /** Refreshes now and answers with the source as it is after the attempt (its status says how it went). */
    @PostMapping("/{id}/refresh")
    public ResponseEntity<?> refresh(@PathVariable final String realmId, @PathVariable final String id) {
        try {
            return service.refreshNow(realmId, id).map(this::view).<ResponseEntity<?>>map(ResponseEntity::ok)
                    .orElseGet(() -> ResponseEntity.notFound().build());
        } catch (final TrustedListService.RefreshBusyException e) {
            return ResponseEntity.status(HttpStatus.CONFLICT).body(Map.of("message", e.getMessage()));
        }
    }

    private static TrustedListSource.Config config(final TrustedListRequest r) {
        if (r == null) {
            throw new ProviderValidationException(Map.of("name", "The trusted list settings are missing"));
        }
        TrustedListSpec.Format format = null;
        if (r.format() != null && !r.format().isBlank()) {
            try {
                format = TrustedListSpec.Format.valueOf(r.format().trim());
            } catch (final IllegalArgumentException e) {
                throw new ProviderValidationException(Map.of("format",
                        "The format must be ETSI_119612_XML or ETSI_119602_JSON"));
            }
        }
        return new TrustedListSource.Config(r.name(), r.url(), format,
                r.signerCertificates() == null ? "" : r.signerCertificates(), r.serviceTypes(), r.acceptedStatuses(),
                r.territories(), r.graceHours() == null ? 24 : r.graceHours(), r.enabled() == null || r.enabled());
    }

    private TrustedListView view(final TrustedListSource s) {
        final TrustedListSource.Config c = s.config();
        final TrustedListSource.State st = s.state();
        final TrustedListHealth.Status status = service.status(s);
        final List<ListedService> services = service.services(s);
        final List<MemberView> members = service.members(s).stream().map(m -> member(s, m)).toList();
        List<CertificateView> signers;
        try {
            signers = PemCertificates.parse(c.signerCertificates()).stream().map(CertificateView::of).toList();
        } catch (final IllegalArgumentException e) {
            signers = List.of();
        }
        final int anchors = s.state().listOfLists()
                ? members.stream().filter(MemberView::anchorsInUse).mapToInt(MemberView::anchorCount).sum()
                : usable(services);
        return new TrustedListView(s.id(), c.name(), c.url(), c.format().name(), c.signerCertificates(), signers,
                c.serviceTypes(), c.acceptedStatuses(),
                c.acceptedStatuses().isEmpty() ? List.copyOf(TrustedListSpec.DEFAULT_STATUSES) : c.acceptedStatuses(),
                c.territories(), c.graceHours(), c.enabled(), status.name(), status.anchorsUsable(),
                time(st.lastAttemptAt()), time(st.lastSuccessAt()), time(st.listIssuedAt()), time(st.nextUpdate()),
                st.nextUpdate() == null || st.servicesJson() == null ? null
                        : Instant.ofEpochMilli(st.nextUpdate()).plus(Duration.ofHours(c.graceHours())).toString(),
                time(st.nextRefreshAt()), st.sequenceNumber(), st.listsRead(), st.lastError(), services.size(),
                anchors, st.listOfLists(), members);
    }

    private MemberView member(final TrustedListSource source, final TrustedListSource.Member m) {
        final TrustedListHealth.Status status = service.memberStatus(source, m);
        final List<ListedService> services = TrustedListService.decode(m.servicesJson());
        return new MemberView(m.territory(), m.location(), status.name(), status.anchorsUsable(), m.sequenceNumber(),
                time(m.listIssuedAt()), time(m.nextUpdate()), m.nextUpdate() == null || m.servicesJson() == null
                        ? null : Instant.ofEpochMilli(m.nextUpdate()).plus(Duration.ofHours(source.config()
                        .graceHours())).toString(), time(m.lastAttemptAt()), time(m.lastSuccessAt()), m.lastError(),
                services.size(), usable(services));
    }

    private static int usable(final List<ListedService> services) {
        return (int) services.stream().filter(x -> TrustAnchors.trustAnchorProblem(x.certificate()) == null).count();
    }

    private static TrustedListAnchorView anchor(final ListedService s) {
        final X509Certificate c = s.certificate();
        final String problem = TrustAnchors.trustAnchorProblem(c);
        return new TrustedListAnchorView(c.getSubjectX500Principal().getName(X500Principal.RFC2253),
                c.getIssuerX500Principal().getName(X500Principal.RFC2253), c.getSerialNumber().toString(16),
                c.getNotAfter().toInstant().toString(), s.serviceName(), s.provider(), s.country(), s.serviceType(),
                s.status(), problem == null, problem);
    }

    private static String time(final Long millis) {
        return millis == null ? null : Instant.ofEpochMilli(millis).toString();
    }
}
