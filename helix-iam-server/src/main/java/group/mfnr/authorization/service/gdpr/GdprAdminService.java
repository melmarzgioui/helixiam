package group.mfnr.authorization.service.gdpr;

import group.mfnr.authorization.domain.federation.FederatedLinkEntity;
import group.mfnr.authorization.domain.gdpr.GdprConsentRecordDto;
import group.mfnr.authorization.domain.gdpr.GdprEraseDto;
import group.mfnr.authorization.domain.gdpr.GdprEraseResultDto;
import group.mfnr.authorization.domain.gdpr.GdprExportDto;
import group.mfnr.authorization.domain.gdpr.GdprExportDto.GdprCredentialMeta;
import group.mfnr.authorization.domain.gdpr.GdprExportDto.GdprFederatedLink;
import group.mfnr.authorization.domain.gdpr.GdprExportDto.GdprLoginEvent;
import group.mfnr.authorization.domain.gdpr.GdprExportDto.GdprOrgMembership;
import group.mfnr.authorization.domain.gdpr.GdprExportDto.GdprProfile;
import group.mfnr.authorization.domain.gdpr.GdprExportDto.GdprRealmMembership;
import group.mfnr.authorization.domain.org.Organization;
import group.mfnr.authorization.domain.tenant.TenantUser;
import group.mfnr.authorization.domain.user.UserCredentials;
import group.mfnr.authorization.domain.user.UserRoles;
import group.mfnr.authorization.domain.user.admin.CredentialSummary;
import group.mfnr.authorization.repository.UserCredentialsRepository;
import group.mfnr.authorization.repository.federation.FederatedLinkRepository;
import group.mfnr.authorization.repository.gdpr.GdprUserMutationRepository;
import group.mfnr.authorization.repository.org.OrganizationMemberRepository;
import group.mfnr.authorization.repository.org.OrganizationRepository;
import group.mfnr.authorization.repository.tenant.TenantUserRepository;
import group.mfnr.authorization.service.user.CredentialAdminService;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * Helix IAM GDPR Art. 15/17/20: the persistence side of data-subject rights.
 *
 * <p><b>Export (Art. 15/20):</b> {@link #export(String, String)} assembles every slice the platform holds
 * about a subject — profile, attributes, realm/org memberships, roles, enrolled credentials (metadata only,
 * via {@link CredentialAdminService}), federated links, the consent ledger and any login/audit events — into
 * a single self-describing {@link GdprExportDto}. <b>No secret material is ever included</b> (no password
 * hash/salt, no TOTP/HOTP secret, no WebAuthn/device keys, no recovery-code hashes, no session blobs).
 *
 * <p><b>Erasure (Art. 17):</b> {@link #erase(GdprEraseDto)} either hard-deletes the global credential (FK
 * cascade drops attributes, tenant links, roles, org memberships, credentials, federated links and consent
 * ledger) or anonymizes it (tombstone every PII field, disable + lock, withdraw consents) while keeping the
 * row for audit integrity.
 */
@Service
public class GdprAdminService {

    private static final Logger LOG = LogManager.getLogger(GdprAdminService.class);

    /** Stable tag so downstream parsers can version the export shape. */
    static final String EXPORT_SCHEMA = "helix.gdpr.export/v1";

    /** Tombstone applied to a username on anonymize (unique-constrained, so it carries the id). */
    private static final String ANON_USERNAME_PREFIX = "anonymized-";

    private final UserCredentialsRepository users;
    private final TenantUserRepository tenantUsers;
    private final OrganizationRepository organizations;
    private final OrganizationMemberRepository orgMembers;
    private final FederatedLinkRepository federatedLinks;
    private final CredentialAdminService credentials;
    private final ConsentLedgerService consents;
    private final GdprUserMutationRepository mutation;

    public GdprAdminService(final UserCredentialsRepository users,
                            final TenantUserRepository tenantUsers,
                            final OrganizationRepository organizations,
                            final OrganizationMemberRepository orgMembers,
                            final FederatedLinkRepository federatedLinks,
                            final CredentialAdminService credentials,
                            final ConsentLedgerService consents,
                            final GdprUserMutationRepository mutation) {
        this.users = users;
        this.tenantUsers = tenantUsers;
        this.organizations = organizations;
        this.orgMembers = orgMembers;
        this.federatedLinks = federatedLinks;
        this.credentials = credentials;
        this.consents = consents;
        this.mutation = mutation;
    }

    /**
     * Assemble the full GDPR export for a subject, or {@code null} when they are not a member of the realm.
     * Read-only; never carries secrets.
     */
    public GdprExportDto export(final String realmId, final String userId) {
        final Optional<TenantUser> link = tenantUsers.findByTenantIdAndUserId(realmId, userId);
        final Optional<UserCredentials> maybeUser = users.findByUserId(userId);
        if (link.isEmpty() || maybeUser.isEmpty()) {
            return null;
        }
        final UserCredentials user = maybeUser.get();

        final GdprProfile profile = new GdprProfile(user.getUsername(), user.getEmail(), false,
                !user.isDisabled(), user.isLocked(), user.isMfaEnabled(),
                user.getCreationDate() == null ? null : user.getCreationDate().getTime());

        final Map<String, String> attributes = user.getUserAttributes() == null ? Map.of() : user.getUserAttributes();

        final List<String> roles = link.get().getRoles() == null ? List.of()
                : link.get().getRoles().stream().map(UserRoles::getName).filter(Objects::nonNull).sorted().toList();

        final List<GdprRealmMembership> realmMemberships = tenantUsers.findAllByUserId(userId).stream()
                .map(tu -> new GdprRealmMembership(tu.getTenantId(), null))
                .toList();

        final List<GdprOrgMembership> orgs = orgMembers.findAllByUserId(userId).stream()
                .map(m -> new GdprOrgMembership(m.getOrgId(), orgName(m.getOrgId()), m.getRole()))
                .toList();

        // Credential metadata only — CredentialAdminService never emits key material.
        final List<GdprCredentialMeta> creds = credentials.list(userId).stream()
                .map(GdprAdminService::toMeta)
                .toList();

        final List<GdprFederatedLink> federated = federatedLinks.findAllByUserId(userId).stream()
                .map(f -> new GdprFederatedLink(f.getIdpAlias(), f.getExternalSubject()))
                .toList();

        final List<GdprConsentRecordDto> consentLedger = consents.list(realmId, userId);

        // Login/audit events are forwarded to an external store in this deployment; none queryable here yet.
        final List<GdprLoginEvent> loginEvents = List.of();

        return new GdprExportDto(System.currentTimeMillis(), EXPORT_SCHEMA, realmId, userId, profile, attributes,
                roles, realmMemberships, orgs, creds, federated, consentLedger, loginEvents);
    }

    /**
     * Erase or anonymize a subject. {@code found == false} when they are not a member of the realm.
     *
     * <p>Hard delete removes the global credential (cascade clears everything FK'd to it). Anonymize keeps
     * the row but tombstones every PII field, disables + locks the account, clears the MFA secret, scrubs the
     * password, removes enrolled factors, withdraws every consent and stamps {@code anonymized_at}.
     */
    @Transactional
    public GdprEraseResultDto erase(final GdprEraseDto erase) {
        final Optional<TenantUser> link = tenantUsers.findByTenantIdAndUserId(erase.realmId(), erase.userId());
        if (link.isEmpty()) {
            return new GdprEraseResultDto(false, erase.isHardDelete() ? GdprEraseDto.MODE_HARD : GdprEraseDto.MODE_ANONYMIZE, erase.userId());
        }
        final Optional<UserCredentials> maybeUser = users.findByUserId(erase.userId());
        if (maybeUser.isEmpty()) {
            // Dangling tenant link with no credential — drop the link and report done.
            tenantUsers.delete(link.get());
            return new GdprEraseResultDto(true, erase.isHardDelete() ? GdprEraseDto.MODE_HARD : GdprEraseDto.MODE_ANONYMIZE, erase.userId());
        }
        final UserCredentials user = maybeUser.get();

        if (erase.isHardDelete()) {
            // FK ON DELETE CASCADE drops user_profile, tenant_user, user_in_role, organization_member,
            // device_credential, webauthn_credential, mfa_recovery_code, federated_link and consent_ledger.
            users.delete(user);
            LOG.info("GDPR hard-delete of user {} in realm {}", erase.userId(), erase.realmId());
            return new GdprEraseResultDto(true, GdprEraseDto.MODE_HARD, erase.userId());
        }

        // Anonymize: tombstone PII, disable auth, strip factors, withdraw consents, keep the row for audit.
        user.setUsername(ANON_USERNAME_PREFIX + user.getUserId());
        user.setEmail(null);
        user.setPassword(null);
        user.setPasswordSaltValue(null);
        user.setMfaSecret(null);
        user.setMfaEnabled(false);
        user.setDisabled(true);
        user.setAccountLocked(true);
        if (user.getUserAttributes() != null) {
            user.getUserAttributes().clear();
        }
        users.save(user);
        mutation.markAnonymized(user.getUserId());

        // Strip every enrolled factor (each delete is store-scoped + ownership-guarded inside the service).
        credentials.list(erase.userId()).forEach(c -> credentials.revoke(erase.userId(), c.type(), c.id()));

        // Withdraw any still-active consents across all clients in this realm.
        consents.list(erase.realmId(), erase.userId()).stream()
                .filter(c -> c.withdrawnAt() == null)
                .map(GdprConsentRecordDto::clientId)
                .distinct()
                .forEach(clientId -> consents.withdraw(
                        new group.mfnr.authorization.domain.gdpr.GdprConsentWithdrawDto(erase.realmId(), erase.userId(), clientId)));

        LOG.info("GDPR anonymize of user {} in realm {}", erase.userId(), erase.realmId());
        return new GdprEraseResultDto(true, GdprEraseDto.MODE_ANONYMIZE, erase.userId());
    }

    private String orgName(final String orgId) {
        return organizations.findById(orgId).map(Organization::getName).orElse(orgId);
    }

    private static GdprCredentialMeta toMeta(final CredentialSummary s) {
        return new GdprCredentialMeta(s.type(), s.id(), s.label(), s.detail(), s.createdAt(), s.lastUsedAt());
    }
}
