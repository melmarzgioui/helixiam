package group.mfnr.authorization.service.org;

import group.mfnr.authorization.domain.org.Organization;
import group.mfnr.authorization.domain.org.OrganizationMember;
import group.mfnr.authorization.domain.org.admin.OrgDto;
import group.mfnr.authorization.domain.org.admin.OrgMemberDto;
import group.mfnr.authorization.domain.org.admin.OrgMembershipDto;
import group.mfnr.authorization.domain.org.admin.OrgRef;
import group.mfnr.authorization.domain.org.admin.OrgWriteDto;
import group.mfnr.authorization.domain.tenant.Tenant;
import group.mfnr.authorization.repository.UserCredentialsRepository;
import group.mfnr.authorization.repository.org.OrganizationMemberRepository;
import group.mfnr.authorization.repository.org.OrganizationRepository;
import group.mfnr.authorization.repository.tenant.TenantRepository;
import group.mfnr.authorization.repository.tenant.TenantUserRepository;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * Helix IAM Organizations: B2B multitenancy within a realm (Keycloak Organizations / WorkOS-class). An
 * organization is a named tenant grouping of users, with one or more email domains for domain-based
 * membership. Members carry a role within the org ({@code member}/{@code admin}). This is the persistence
 * side of the console's Organizations screen; it also resolves a user's memberships for token enrichment.
 *
 * <p>Invariant guards throw {@link IllegalArgumentException} on malformed AMQP input — never on the admin
 * REST path, where Bean Validation + {@code AdminValidationAdvice} produce a 400 first.
 */
@Service
public class OrganizationAdminService {

    private static final Logger LOG = LogManager.getLogger(OrganizationAdminService.class);
    private static final String DEFAULT_MEMBER_ROLE = "member";

    private final OrganizationRepository organizations;
    private final OrganizationMemberRepository members;
    private final UserCredentialsRepository users;
    private final TenantUserRepository tenantUsers;
    private final TenantRepository tenants;

    public OrganizationAdminService(final OrganizationRepository organizations,
                                    final OrganizationMemberRepository members,
                                    final UserCredentialsRepository users,
                                    final TenantUserRepository tenantUsers,
                                    final TenantRepository tenants) {
        this.organizations = organizations;
        this.members = members;
        this.users = users;
        this.tenantUsers = tenantUsers;
        this.tenants = tenants;
    }

    /** Every organization in the realm, each with its member count. */
    public List<OrgDto> list(final String realmId) {
        return organizations.findAllByTenantId(realmId).stream().map(this::toDto).toList();
    }

    /** A single organization, when it exists in this realm. */
    public Optional<OrgDto> get(final String realmId, final String orgId) {
        return organizations.findById(orgId)
                .filter(o -> realmId.equals(o.getTenantId()))
                .map(this::toDto);
    }

    /** Creates an organization; the name must be unique per realm. */
    @Transactional
    public OrgDto create(final OrgWriteDto write) {
        if (write.name() == null || write.name().isBlank()) {
            throw new IllegalArgumentException("Organization name is required.");
        }
        ensureTenant(write.realmId());
        if (organizations.existsByTenantIdAndName(write.realmId(), write.name().trim())) {
            throw new IllegalArgumentException("An organization named '" + write.name().trim() + "' already exists.");
        }
        final Organization saved = organizations.save(new Organization(
                write.realmId(), write.name().trim(), blankToNull(write.displayName()),
                joinDomains(write.domains()), write.enabled()));
        LOG.debug("Created organization {} in realm {}", saved.getName(), write.realmId());
        return toDto(saved);
    }

    /** Updates an organization's name/displayName/domains/enabled; {@code null} if it isn't in this realm. */
    @Transactional
    public OrgDto update(final OrgWriteDto write) {
        final Optional<Organization> existing = organizations.findById(write.orgId());
        if (existing.isEmpty() || !write.realmId().equals(existing.get().getTenantId())) {
            return null;
        }
        if (write.name() == null || write.name().isBlank()) {
            throw new IllegalArgumentException("Organization name is required.");
        }
        final String name = write.name().trim();
        // A rename must not collide with another org's name in the same realm.
        organizations.findByTenantIdAndName(write.realmId(), name).ifPresent(other -> {
            if (!other.getOrgId().equals(write.orgId())) {
                throw new IllegalArgumentException("An organization named '" + name + "' already exists.");
            }
        });
        final Organization org = existing.get();
        org.setName(name);
        org.setDisplayName(blankToNull(write.displayName()));
        org.setDomains(joinDomains(write.domains()));
        org.setEnabled(write.enabled());
        return toDto(organizations.save(org));
    }

    /** Deletes an organization and its memberships; {@code false} if it isn't in this realm. */
    @Transactional
    public boolean delete(final String realmId, final String orgId) {
        final Optional<Organization> org = organizations.findById(orgId);
        if (org.isEmpty() || !realmId.equals(org.get().getTenantId())) {
            return false;
        }
        organizations.delete(org.get()); // member rows cascade via FK
        LOG.debug("Deleted organization {} from realm {}", orgId, realmId);
        return true;
    }

    /** The users who belong to an organization, with their usernames and role within the org. */
    public List<OrgMemberDto> listMembers(final OrgRef ref) {
        return members.findAllByOrgId(ref.orgId()).stream()
                .map(m -> users.findByUserId(m.getUserId())
                        .map(u -> new OrgMemberDto(u.getUserId(), u.getUsername(), m.getRole()))
                        .orElse(new OrgMemberDto(m.getUserId(), m.getUserId(), m.getRole())))
                .toList();
    }

    /**
     * Adds a user to an organization with a role (defaults to {@code member}); idempotent — updates the
     * role if already a member. {@code false} if the user is not a member of the realm or the org is absent.
     */
    @Transactional
    public boolean addMember(final OrgRef ref) {
        if (organizations.findById(ref.orgId()).filter(o -> ref.realmId().equals(o.getTenantId())).isEmpty()) {
            return false;
        }
        if (tenantUsers.findByTenantIdAndUserId(ref.realmId(), ref.userId()).isEmpty()) {
            return false;
        }
        final String role = ref.role() == null || ref.role().isBlank() ? DEFAULT_MEMBER_ROLE : ref.role().trim();
        members.findByOrgIdAndUserId(ref.orgId(), ref.userId()).ifPresentOrElse(existing -> {
            existing.setRole(role);
            members.save(existing);
        }, () -> {
            members.save(new OrganizationMember(ref.orgId(), ref.userId(), role));
            LOG.debug("Added user {} to organization {} as {}", ref.userId(), ref.orgId(), role);
        });
        return true;
    }

    /** Removes a user from an organization; {@code false} if they weren't a member. */
    @Transactional
    public boolean removeMember(final OrgRef ref) {
        return members.findByOrgIdAndUserId(ref.orgId(), ref.userId()).map(m -> {
            members.delete(m);
            return true;
        }).orElse(false);
    }

    /**
     * A user's organization memberships, shaped for the {@code organizations} token claim — one entry per
     * org with its name and the user's roles in it. Mutable collections so the SAS token serializer accepts
     * them. Restricted to enabled orgs (a disabled org is not advertised in tokens).
     */
    public List<OrgMembershipDto> membershipsForUser(final String userId) {
        final List<OrgMembershipDto> out = new ArrayList<>();
        for (final OrganizationMember m : members.findAllByUserId(userId)) {
            organizations.findById(m.getOrgId())
                    .filter(Organization::isEnabled)
                    .ifPresent(org -> {
                        final List<String> roles = new ArrayList<>();
                        roles.add(m.getRole() == null || m.getRole().isBlank() ? DEFAULT_MEMBER_ROLE : m.getRole());
                        out.add(new OrgMembershipDto(org.getOrgId(), org.getName(), roles));
                    });
        }
        return out;
    }

    private OrgDto toDto(final Organization o) {
        return new OrgDto(o.getTenantId(), o.getOrgId(), o.getName(), o.getDisplayName(),
                splitDomains(o.getDomains()), o.isEnabled(), members.countByOrgId(o.getOrgId()), null);
    }

    /** An org's realm link FKs to {@code tenant}; a realm may exist only as config, so back-fill it. */
    private void ensureTenant(final String realmId) {
        if (tenants.findById(realmId).isEmpty()) {
            final Tenant tenant = new Tenant();
            tenant.setTenantId(realmId);
            tenant.setName(realmId);
            tenants.save(tenant);
        }
    }

    /** Normalises a list of domains to a lowercase, blank-stripped, comma-joined column value ({@code null} = none). */
    private static String joinDomains(final List<String> domains) {
        if (domains == null) {
            return null;
        }
        final List<String> cleaned = domains.stream()
                .filter(Objects::nonNull)
                .map(d -> d.trim().toLowerCase())
                .filter(d -> !d.isEmpty())
                .distinct()
                .toList();
        return cleaned.isEmpty() ? null : String.join(",", cleaned);
    }

    /** Splits the stored comma-joined domains back into a (mutable) list. */
    private static List<String> splitDomains(final String domains) {
        final List<String> out = new ArrayList<>();
        if (domains != null && !domains.isBlank()) {
            Arrays.stream(domains.split(",")).map(String::trim).filter(d -> !d.isEmpty()).forEach(out::add);
        }
        return out;
    }

    private static String blankToNull(final String value) {
        return value == null || value.isBlank() ? null : value.trim();
    }
}
