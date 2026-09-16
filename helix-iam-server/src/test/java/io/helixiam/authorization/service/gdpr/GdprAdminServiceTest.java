/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.service.gdpr;

import io.helixiam.authorization.domain.federation.FederatedLinkEntity;
import io.helixiam.authorization.domain.gdpr.GdprConsentRecordDto;
import io.helixiam.authorization.domain.gdpr.GdprEraseDto;
import io.helixiam.authorization.domain.gdpr.GdprEraseResultDto;
import io.helixiam.authorization.domain.gdpr.GdprExportDto;
import io.helixiam.authorization.domain.org.Organization;
import io.helixiam.authorization.domain.org.OrganizationMember;
import io.helixiam.authorization.domain.tenant.TenantUser;
import io.helixiam.authorization.domain.user.UserCredentials;
import io.helixiam.authorization.domain.user.UserRoles;
import io.helixiam.authorization.domain.user.admin.CredentialSummary;
import io.helixiam.authorization.repository.UserCredentialsRepository;
import io.helixiam.authorization.repository.federation.FederatedLinkRepository;
import io.helixiam.authorization.repository.gdpr.GdprUserMutationRepository;
import io.helixiam.authorization.repository.org.OrganizationMemberRepository;
import io.helixiam.authorization.repository.org.OrganizationRepository;
import io.helixiam.authorization.repository.tenant.TenantUserRepository;
import io.helixiam.authorization.service.user.CredentialAdminService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Helix IAM GDPR Art. 15/17: export assembles every slice without secrets; erasure anonymizes (tombstone +
 * disable + cascade) or hard-deletes (cascade via FK).
 */
class GdprAdminServiceTest {

    private UserCredentialsRepository users;
    private TenantUserRepository tenantUsers;
    private OrganizationRepository organizations;
    private OrganizationMemberRepository orgMembers;
    private FederatedLinkRepository federatedLinks;
    private CredentialAdminService credentials;
    private ConsentLedgerService consents;
    private GdprUserMutationRepository mutation;
    private GdprAdminService service;

    @BeforeEach
    void setUp() {
        users = mock(UserCredentialsRepository.class);
        tenantUsers = mock(TenantUserRepository.class);
        organizations = mock(OrganizationRepository.class);
        orgMembers = mock(OrganizationMemberRepository.class);
        federatedLinks = mock(FederatedLinkRepository.class);
        credentials = mock(CredentialAdminService.class);
        consents = mock(ConsentLedgerService.class);
        mutation = mock(GdprUserMutationRepository.class);
        service = new GdprAdminService(users, tenantUsers, organizations, orgMembers, federatedLinks,
                credentials, consents, mutation);
    }

    @Test
    void export_assemblesAllSlices_andCarriesNoSecrets() {
        final UserCredentials user = user("u-1", "alice", "alice@example.com");
        user.setPassword("$argon2id$SECRET-HASH");
        user.setMfaSecret("TOTP-SEED-SECRET");
        user.setMfaEnabled(true);
        user.getUserAttributes().put("department", "Tax");
        final TenantUser link = tenantUser("gov", "u-1", new UserRoles("auditor", "gov"));

        when(tenantUsers.findByTenantIdAndUserId("gov", "u-1")).thenReturn(Optional.of(link));
        when(users.findByUserId("u-1")).thenReturn(Optional.of(user));
        when(tenantUsers.findAllByUserId("u-1")).thenReturn(List.of(link));
        when(orgMembers.findAllByUserId("u-1")).thenReturn(List.of(new OrganizationMember("org-1", "u-1", "member")));
        when(organizations.findById("org-1")).thenReturn(Optional.of(new Organization("gov", "Acme", "Acme Corp", null, true)));
        when(credentials.list("u-1")).thenReturn(List.of(
                new CredentialSummary("totp", "totp", "Authenticator app (TOTP)", "Time-based", null, null, true)));
        when(federatedLinks.findAllByUserId("u-1")).thenReturn(List.of(new FederatedLinkEntity("google", "ext-123", "u-1")));
        when(consents.list("gov", "u-1")).thenReturn(List.of(
                new GdprConsentRecordDto("c-1", "gov", "u-1", "portal", List.of("openid"), 1L, null)));

        final GdprExportDto export = service.export("gov", "u-1");

        assertEquals("u-1", export.userId());
        assertEquals("gov", export.realmId());
        assertEquals("alice", export.profile().username());
        assertTrue(export.profile().mfaEnabled());
        assertEquals("Tax", export.attributes().get("department"));
        assertEquals(List.of("auditor"), export.roles());
        assertEquals(1, export.realmMemberships().size());
        assertEquals(1, export.organizations().size());
        assertEquals("Acme", export.organizations().get(0).name());
        assertEquals(1, export.credentials().size());
        assertEquals("totp", export.credentials().get(0).type());
        assertEquals(1, export.federatedLinks().size());
        assertEquals("google", export.federatedLinks().get(0).idpAlias());
        assertEquals(1, export.consents().size());

        // SECRET-OMISSION: no field anywhere in the serialized export may carry password/MFA key material.
        final String dump = export.toString();
        assertFalse(dump.contains("SECRET-HASH"), "password hash must never appear in the export");
        assertFalse(dump.contains("TOTP-SEED-SECRET"), "MFA secret must never appear in the export");
    }

    @Test
    void export_returnsNull_whenNotMemberOfRealm() {
        when(tenantUsers.findByTenantIdAndUserId("gov", "ghost")).thenReturn(Optional.empty());
        assertNull(service.export("gov", "ghost"));
    }

    @Test
    void erase_hardDelete_removesCredentialRow_forCascade() {
        final UserCredentials user = user("u-1", "alice", "alice@example.com");
        when(tenantUsers.findByTenantIdAndUserId("gov", "u-1")).thenReturn(Optional.of(tenantUser("gov", "u-1")));
        when(users.findByUserId("u-1")).thenReturn(Optional.of(user));

        final GdprEraseResultDto result = service.erase(new GdprEraseDto("gov", "u-1", "hard"));

        assertTrue(result.found());
        assertEquals("hard", result.mode());
        verify(users).delete(user);
        verify(users, never()).save(any());
    }

    @Test
    void erase_anonymize_tombstonesPii_disablesAccount_andStampsMarker() {
        final UserCredentials user = user("u-1", "alice", "alice@example.com");
        user.setPassword("$argon2id$SECRET");
        user.setMfaSecret("SEED");
        user.setMfaEnabled(true);
        user.getUserAttributes().put("department", "Tax");
        when(tenantUsers.findByTenantIdAndUserId("gov", "u-1")).thenReturn(Optional.of(tenantUser("gov", "u-1")));
        when(users.findByUserId("u-1")).thenReturn(Optional.of(user));
        when(credentials.list("u-1")).thenReturn(List.of());
        when(consents.list("gov", "u-1")).thenReturn(List.of());

        final GdprEraseResultDto result = service.erase(new GdprEraseDto("gov", "u-1", "anonymize"));

        assertTrue(result.found());
        assertEquals("anonymize", result.mode());
        assertFalse(user.getUsername().equals("alice"), "username is tombstoned");
        assertTrue(user.getUsername().contains("u-1"), "tombstone carries the id");
        assertNull(user.getEmail());
        assertNull(user.getPassword());
        assertNull(user.getMfaSecret());
        assertFalse(user.isMfaEnabled());
        assertTrue(user.isDisabled());
        assertTrue(user.isLocked());
        assertTrue(user.getUserAttributes().isEmpty(), "attributes are cleared");
        verify(users).save(user);
        verify(mutation).markAnonymized("u-1");
        verify(users, never()).delete(any());
    }

    @Test
    void erase_returnsNotFound_whenNotMemberOfRealm() {
        when(tenantUsers.findByTenantIdAndUserId("gov", "ghost")).thenReturn(Optional.empty());
        final GdprEraseResultDto result = service.erase(new GdprEraseDto("gov", "ghost", "anonymize"));
        assertFalse(result.found());
    }

    @Test
    void erase_anonymize_withdrawsActiveConsents() {
        final UserCredentials user = user("u-1", "alice", "alice@example.com");
        when(tenantUsers.findByTenantIdAndUserId("gov", "u-1")).thenReturn(Optional.of(tenantUser("gov", "u-1")));
        when(users.findByUserId("u-1")).thenReturn(Optional.of(user));
        when(credentials.list("u-1")).thenReturn(List.of());
        when(consents.list("gov", "u-1")).thenReturn(List.of(
                new GdprConsentRecordDto("c-1", "gov", "u-1", "portal", List.of("openid"), 1L, null)));

        service.erase(new GdprEraseDto("gov", "u-1", "anonymize"));

        verify(consents).withdraw(any());
    }

    private static UserCredentials user(final String id, final String username, final String email) {
        final UserCredentials u = new UserCredentials();
        u.setUserId(id);
        u.setUsername(username);
        u.setEmail(email);
        return u;
    }

    private static TenantUser tenantUser(final String tenantId, final String userId, final UserRoles... roles) {
        final TenantUser tu = new TenantUser();
        tu.setTenantId(tenantId);
        tu.setUserId(userId);
        for (final UserRoles r : roles) {
            tu.getRoles().add(r);
        }
        return tu;
    }
}
