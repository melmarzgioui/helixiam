/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.service.scope;

import io.helixiam.authorization.domain.scope.ClaimDef;
import io.helixiam.authorization.domain.scope.ClientScope;
import io.helixiam.authorization.domain.scope.ScopeClaim;
import io.helixiam.authorization.domain.scope.admin.ClaimDto;
import io.helixiam.authorization.domain.scope.admin.ClaimWriteDto;
import io.helixiam.authorization.domain.scope.admin.ClientScopeDto;
import io.helixiam.authorization.domain.scope.admin.ScopeDetailDto;
import io.helixiam.authorization.domain.scope.admin.ScopeRef;
import io.helixiam.authorization.domain.scope.admin.ScopeWriteDto;
import io.helixiam.authorization.domain.scope.admin.SubjectClaimDto;
import io.helixiam.authorization.domain.realm.RealmConfig;
import io.helixiam.authorization.domain.tenant.Tenant;
import io.helixiam.authorization.repository.ServiceProviderRepository;
import io.helixiam.authorization.repository.realm.RealmConfigRepository;
import io.helixiam.authorization.repository.scope.ClaimDefRepository;
import io.helixiam.authorization.repository.scope.ClientScopeRepository;
import io.helixiam.authorization.repository.scope.ScopeClaimRepository;
import io.helixiam.authorization.repository.tenant.TenantRepository;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Helix IAM E8.5: claim-catalogue + client-scope administration. A realm's claim *types* live in
 * {@code claim_def}; client scopes ({@code client_scope}) bundle claims via {@code scope_claim}. On
 * first access a realm is seeded with the default catalogue and scopes, so the console is never empty.
 * Backs the Claims screen, the Client scopes table, and the scope detail page (add/remove claims).
 */
@Service
public class ClaimScopeAdminService {

    private static final Logger LOG = LogManager.getLogger(ClaimScopeAdminService.class);
    private static final int PREVIEW = 3;

    /** Default scopes and the claim keys they bundle (key, label, placeholder, mandatory). */
    private record SeedClaim(String key, String label, String placeholder, boolean mandatory) {
        SeedClaim(final String key, final String label, final String placeholder) {
            this(key, label, placeholder, false);
        }
    }

    /**
     * The WSO2-style base OIDC scopes shipped out of the box — exactly the standard {@code openid},
     * {@code profile}, {@code email}, {@code address} and {@code phone} scope claims. Order is preserved.
     * Realms can add/edit/remove claims afterwards.
     */
    private static final Map<String, List<SeedClaim>> SEED = new java.util.LinkedHashMap<>();

    static {
        SEED.put("OpenID", List.of(
                new SeedClaim("sub", "Subject identifier", null, true)));
        SEED.put("Profile", List.of(
                new SeedClaim("name", "Full name", "Alice de Vries"),
                new SeedClaim("family_name", "Family name", "de Vries", true),
                new SeedClaim("given_name", "Given name", "Alice", true),
                new SeedClaim("middle_name", "Middle name", null),
                new SeedClaim("nickname", "Nickname", null),
                new SeedClaim("preferred_username", "Preferred username", "alice"),
                new SeedClaim("profile", "Profile URL", null),
                new SeedClaim("picture", "Picture URL", null),
                new SeedClaim("website", "Website", null),
                new SeedClaim("gender", "Gender", null),
                new SeedClaim("birthdate", "Birthdate", "1990-01-31"),
                new SeedClaim("zoneinfo", "Time zone", "Europe/Amsterdam"),
                new SeedClaim("locale", "Locale", "nl-NL"),
                new SeedClaim("updated_at", "Profile updated at", null)));
        SEED.put("Email", List.of(
                new SeedClaim("email", "Email", "alice@organisation.nl", true),
                new SeedClaim("email_verified", "Email verified", null)));
        SEED.put("Address", List.of(
                new SeedClaim("address", "Address (formatted)", null),
                new SeedClaim("street_address", "Street address", null),
                new SeedClaim("locality", "City / locality", "Arnhem"),
                new SeedClaim("region", "Region / province", "Gelderland"),
                new SeedClaim("postal_code", "Postal code", "6811"),
                new SeedClaim("country", "Country", "Netherlands")));
        SEED.put("Phone", List.of(
                new SeedClaim("phone_number", "Phone number", "+31 6 1234 5678"),
                new SeedClaim("phone_number_verified", "Phone verified", null)));
    }

    /** Default subject source when a realm has not chosen one: the {@code sub} claim itself. */
    static final String DEFAULT_SUBJECT_CLAIM = "sub";

    private final ClaimDefRepository claims;
    private final ClientScopeRepository scopes;
    private final ScopeClaimRepository scopeClaims;
    private final TenantRepository tenants;
    private final RealmConfigRepository realmConfigs;
    private final ServiceProviderRepository serviceProviders;

    private final io.helixiam.authorization.repository.application.ApplicationRepository applications;

    public ClaimScopeAdminService(final ClaimDefRepository claims, final ClientScopeRepository scopes,
                                  final ScopeClaimRepository scopeClaims, final TenantRepository tenants,
                                  final RealmConfigRepository realmConfigs, final ServiceProviderRepository serviceProviders,
                                  final io.helixiam.authorization.repository.application.ApplicationRepository applications) {
        this.claims = claims;
        this.scopes = scopes;
        this.scopeClaims = scopeClaims;
        this.tenants = tenants;
        this.realmConfigs = realmConfigs;
        this.serviceProviders = serviceProviders;
        this.applications = applications;
    }

    // ---- Claims catalogue -------------------------------------------------------------------------

    /** Every claim type in the realm's catalogue (seeding the defaults on first access). */
    @Transactional
    public List<ClaimDto> listClaims(final String realmId) {
        ensureSeeded(realmId);
        return claims.findAllByTenantId(realmId).stream().map(this::toClaimDto).toList();
    }

    /** Adds a claim type to the catalogue; idempotent on key. */
    @Transactional
    public ClaimDto createClaim(final ClaimWriteDto write) {
        // Invariant guard: a catalogue claim must have a key.
        if (write.key() == null || write.key().isBlank()) {
            throw new IllegalArgumentException("Claim key is required.");
        }
        ensureTenant(write.realmId());
        if (claims.existsByTenantIdAndClaimKey(write.realmId(), write.key())) {
            return claims.findAllByTenantId(write.realmId()).stream()
                    .filter(c -> write.key().equals(c.getClaimKey())).findFirst().map(this::toClaimDto).orElse(null);
        }
        final ClaimDef saved = claims.save(new ClaimDef(write.realmId(), write.key(), write.label(), write.placeholder(), write.mandatory()));
        LOG.debug("Added claim {} to {} catalogue", write.key(), write.realmId());
        return toClaimDto(saved);
    }

    /** Edits a catalogue claim's label, example and mandatory flag (the key is immutable); {@code null} if absent. */
    @Transactional
    public ClaimDto updateClaim(final ClaimWriteDto write) {
        final Optional<ClaimDef> existing = claims.findById(write.claimId());
        if (existing.isEmpty() || !write.realmId().equals(existing.get().getTenantId())) {
            return null;
        }
        final ClaimDef claim = existing.get();
        claim.setLabel(write.label());
        claim.setPlaceholder(write.placeholder());
        claim.setMandatory(write.mandatory());
        return toClaimDto(claims.save(claim));
    }

    /** Removes a claim type (and every scope mapping of it via FK cascade); {@code false} if absent. */
    @Transactional
    public boolean deleteClaim(final String realmId, final String claimId) {
        final Optional<ClaimDef> claim = claims.findById(claimId);
        if (claim.isEmpty() || !realmId.equals(claim.get().getTenantId())) {
            return false;
        }
        claims.delete(claim.get());
        return true;
    }

    // ---- Client scopes ----------------------------------------------------------------------------

    /** Every client scope in the realm, with claim counts + a short preview (seeding defaults first). */
    @Transactional
    public List<ClientScopeDto> listScopes(final String realmId) {
        ensureSeeded(realmId);
        return scopes.findAllByTenantId(realmId).stream().map(this::toScopeDto).toList();
    }

    /** A scope with its full claim list. */
    @Transactional
    public ScopeDetailDto getScope(final String realmId, final String scopeId) {
        ensureSeeded(realmId);
        final Optional<ClientScope> scope = scopes.findById(scopeId);
        if (scope.isEmpty() || !realmId.equals(scope.get().getTenantId())) {
            return null;
        }
        return new ScopeDetailDto(realmId, scopeId, scope.get().getName(), scope.get().getDescription(),
                claimsOfScope(scopeId));
    }

    /** Creates a client scope; idempotent on name. */
    @Transactional
    public ClientScopeDto createScope(final ScopeWriteDto write) {
        // Invariant guard: a client scope must have a name.
        if (write.name() == null || write.name().isBlank()) {
            throw new IllegalArgumentException("Scope name is required.");
        }
        ensureTenant(write.realmId());
        if (scopes.existsByTenantIdAndName(write.realmId(), write.name())) {
            return scopes.findAllByTenantId(write.realmId()).stream()
                    .filter(s -> write.name().equals(s.getName())).findFirst().map(this::toScopeDto).orElse(null);
        }
        final ClientScope saved = scopes.save(new ClientScope(write.realmId(), write.name(), write.description()));
        return toScopeDto(saved);
    }

    /** Deletes a client scope (mappings cascade); {@code false} if it isn't in this realm. */
    @Transactional
    public boolean deleteScope(final String realmId, final String scopeId) {
        final Optional<ClientScope> scope = scopes.findById(scopeId);
        if (scope.isEmpty() || !realmId.equals(scope.get().getTenantId())) {
            return false;
        }
        scopes.delete(scope.get());
        return true;
    }

    /** Maps a catalogue claim into a scope; idempotent. */
    @Transactional
    public boolean addClaim(final ScopeRef ref) {
        if (scopeClaims.findByScopeIdAndClaimId(ref.scopeId(), ref.claimId()).isEmpty()) {
            scopeClaims.save(new ScopeClaim(ref.scopeId(), ref.claimId()));
            LOG.debug("Mapped claim {} into scope {}", ref.claimId(), ref.scopeId());
        }
        return true;
    }

    /** Removes a claim mapping from a scope; {@code false} if it wasn't mapped. */
    @Transactional
    public boolean removeClaim(final ScopeRef ref) {
        return scopeClaims.findByScopeIdAndClaimId(ref.scopeId(), ref.claimId()).map(sc -> {
            scopeClaims.delete(sc);
            return true;
        }).orElse(false);
    }

    // ---- Subject identifier (which claim becomes `sub`) -------------------------------------------

    /** The catalogue claim key whose value populates the OIDC {@code sub}; defaults to {@code sub}. */
    @Transactional(readOnly = true)
    public String getSubjectClaim(final String realmId) {
        return realmConfigs.findById(realmId)
                .map(RealmConfig::getSubjectClaim)
                .filter(s -> s != null && !s.isBlank())
                .orElse(DEFAULT_SUBJECT_CLAIM);
    }

    /**
     * The effective subject claim for a client: its own override if set, otherwise the realm default,
     * otherwise {@code sub}. This is the precedence a token's {@code sub} mapper should follow.
     */
    @Transactional(readOnly = true)
    public String resolveSubjectClaim(final String realmId, final String clientSubjectClaim) {
        if (clientSubjectClaim != null && !clientSubjectClaim.isBlank()) {
            return clientSubjectClaim;
        }
        return getSubjectClaim(realmId);
    }

    /**
     * The effective subject claim for an OAuth client ({@code client_id} <b>within {@code realmId}</b>),
     * resolving the client override, then the realm default, then {@code sub}. Used by the token
     * {@code sub} mapper. Realm-scoped so a client id reused across realms resolves the right client.
     */
    @Transactional(readOnly = true)
    public String resolveSubjectClaimForClient(final String realmId, final String clientId) {
        return serviceProviders.findByClientIdAndRealmIdAndDeleted(clientId, realmId, false)
                .map(c -> {
                    // Application model: the parent app's shared subject claim takes precedence.
                    if (c.getApplicationId() != null) {
                        final String appClaim = applications.findById(c.getApplicationId())
                                .map(io.helixiam.authorization.domain.application.ApplicationEntity::getSubjectClaim)
                                .filter(s -> s != null && !s.isBlank())
                                .orElse(null);
                        if (appClaim != null) {
                            return appClaim;
                        }
                    }
                    return resolveSubjectClaim(c.getTenantId(), c.getSubjectClaim());
                })
                .orElse(DEFAULT_SUBJECT_CLAIM);
    }

    /** Chooses which catalogue claim populates the OIDC {@code sub} for the realm. */
    @Transactional
    public SubjectClaimDto setSubjectClaim(final SubjectClaimDto write) {
        ensureTenant(write.realmId());
        final RealmConfig config = realmConfigs.findById(write.realmId())
                .orElseGet(() -> RealmConfig.defaults(write.realmId()));
        config.setSubjectClaim(write.claimKey());
        realmConfigs.save(config);
        LOG.debug("Realm {} subject claim set to {}", write.realmId(), write.claimKey());
        return new SubjectClaimDto(write.realmId(), write.claimKey());
    }

    // ---- helpers ----------------------------------------------------------------------------------

    private List<ClaimDto> claimsOfScope(final String scopeId) {
        return scopeClaims.findAllByScopeId(scopeId).stream()
                .map(sc -> claims.findById(sc.getClaimId()).map(this::toClaimDto).orElse(null))
                .filter(java.util.Objects::nonNull)
                .toList();
    }

    private ClientScopeDto toScopeDto(final ClientScope s) {
        final List<ClaimDto> mapped = claimsOfScope(s.getScopeId());
        final List<String> preview = mapped.stream().limit(PREVIEW).map(ClaimDto::label).toList();
        return new ClientScopeDto(s.getTenantId(), s.getScopeId(), s.getName(), s.getDescription(), mapped.size(), preview);
    }

    private ClaimDto toClaimDto(final ClaimDef c) {
        return new ClaimDto(c.getTenantId(), c.getClaimId(), c.getClaimKey(), c.getLabel(), c.getPlaceholder(), c.isMandatory());
    }

    /** Seeds the default catalogue + scopes for a realm that has none yet. Idempotent. */
    private void ensureSeeded(final String realmId) {
        if (scopes.countByTenantId(realmId) > 0) {
            return;
        }
        ensureTenant(realmId);
        SEED.forEach((scopeName, seedClaims) -> {
            final ClientScope scope = scopes.save(new ClientScope(realmId, scopeName, scopeName + " claims"));
            for (final SeedClaim sc : seedClaims) {
                final ClaimDef claim = claims.existsByTenantIdAndClaimKey(realmId, sc.key())
                        ? claims.findAllByTenantId(realmId).stream().filter(c -> sc.key().equals(c.getClaimKey())).findFirst().orElseGet(() -> claims.save(new ClaimDef(realmId, sc.key(), sc.label(), sc.placeholder(), sc.mandatory())))
                        : claims.save(new ClaimDef(realmId, sc.key(), sc.label(), sc.placeholder(), sc.mandatory()));
                scopeClaims.save(new ScopeClaim(scope.getScopeId(), claim.getClaimId()));
            }
        });
        LOG.info("Seeded default client scopes + claim catalogue for realm {}", realmId);
    }

    private void ensureTenant(final String realmId) {
        if (tenants.findById(realmId).isEmpty()) {
            final Tenant tenant = new Tenant();
            tenant.setTenantId(realmId);
            tenants.save(tenant);
        }
    }
}
