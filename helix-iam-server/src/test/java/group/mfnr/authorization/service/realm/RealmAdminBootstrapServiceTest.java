package group.mfnr.authorization.service.realm;

import group.mfnr.authorization.domain.tenant.Tenant;
import group.mfnr.authorization.domain.tenant.TenantUser;
import group.mfnr.authorization.domain.user.UserCredentials;
import group.mfnr.authorization.domain.user.UserInRole;
import group.mfnr.authorization.domain.user.UserRoles;
import group.mfnr.authorization.repository.UserCredentialsRepository;
import group.mfnr.authorization.repository.UserInRoleRepository;
import group.mfnr.authorization.repository.UserRolesRepository;
import group.mfnr.authorization.repository.tenant.TenantRepository;
import group.mfnr.authorization.repository.tenant.TenantUserRepository;
import group.mfnr.authorization.service.PasswordEncoderService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/** Helix IAM: every realm is bootstrapped with an admin role + admin user (master = admin/admin, env-overridable). */
class RealmAdminBootstrapServiceTest {

    private TenantRepository tenants;
    private UserRolesRepository roles;
    private UserCredentialsRepository users;
    private TenantUserRepository links;
    private UserInRoleRepository userRoles;
    private PasswordEncoderService encoder;
    private RealmAdminBootstrapService service;

    @BeforeEach
    void setUp() {
        tenants = mock(TenantRepository.class);
        roles = mock(UserRolesRepository.class);
        users = mock(UserCredentialsRepository.class);
        links = mock(TenantUserRepository.class);
        userRoles = mock(UserInRoleRepository.class);
        encoder = mock(PasswordEncoderService.class);
        when(encoder.encode(any())).thenAnswer(i -> "enc(" + i.getArgument(0) + ")");
        when(roles.save(any(UserRoles.class))).thenAnswer(i -> i.getArgument(0));
        when(links.save(any(TenantUser.class))).thenAnswer(i -> i.getArgument(0));
        service = new RealmAdminBootstrapService(tenants, roles, users, links, userRoles, encoder, "admin", "secretpw");
    }

    private void freshRealm(final String realm, final String adminUsername) {
        when(tenants.findById(realm)).thenReturn(Optional.empty());
        when(roles.findByTenantIdAndName(realm, "admin")).thenReturn(Optional.empty());
        when(users.findByUsername(adminUsername)).thenReturn(Optional.empty());
        when(users.save(any(UserCredentials.class))).thenAnswer(i -> { UserCredentials u = i.getArgument(0); u.setUserId("uid-" + realm); return u; });
        when(links.findByTenantIdAndUserId(realm, "uid-" + realm)).thenReturn(Optional.of(link(realm, "uid-" + realm)));
        when(userRoles.findByRoleIdAndUserId(any(), any())).thenReturn(Optional.empty());
    }

    private static TenantUser link(final String realm, final String userId) {
        final TenantUser l = new TenantUser();
        l.setTenantId(realm); l.setUserId(userId);  // tenantUserId is JPA-generated (no setter)
        return l;
    }

    @Test
    void master_createsAdminRole_adminUser_andAssignment_withConfiguredCreds() {
        freshRealm("master", "admin");
        service.ensureRealmAdmin("master");

        verify(tenants).save(any(Tenant.class));
        final ArgumentCaptor<UserCredentials> uc = ArgumentCaptor.forClass(UserCredentials.class);
        verify(users).save(uc.capture());
        assertEquals("admin", uc.getValue().getUsername());
        assertEquals("enc(secretpw)", uc.getValue().getPassword());
        assertFalse(uc.getValue().isLocked(), "admin must be unlocked");
        assertFalse(uc.getValue().isDisabled(), "admin must be enabled");
        verify(roles).save(any(UserRoles.class));
        verify(userRoles).save(any(UserInRole.class));
    }

    @Test
    void nonMasterRealm_usesRealmQualifiedUsername() {
        freshRealm("acme", "admin-acme");
        service.ensureRealmAdmin("acme");
        final ArgumentCaptor<UserCredentials> uc = ArgumentCaptor.forClass(UserCredentials.class);
        verify(users).save(uc.capture());
        assertEquals("admin-acme", uc.getValue().getUsername());
    }

    @Test
    void idempotent_whenAdminAlreadyExists_doesNotRecreateOrResetPassword() {
        when(tenants.findById("master")).thenReturn(Optional.of(new Tenant()));
        when(roles.findByTenantIdAndName("master", "admin")).thenReturn(Optional.of(new UserRoles("admin", "master")));
        final UserCredentials existing = new UserCredentials(); existing.setUserId("uid-master"); existing.setUsername("admin");
        when(users.findByUsername("admin")).thenReturn(Optional.of(existing));
        when(links.findByTenantIdAndUserId("master", "uid-master")).thenReturn(Optional.of(link("master", "uid-master")));
        when(userRoles.findByRoleIdAndUserId(any(), any())).thenReturn(Optional.of(new UserInRole()));

        service.ensureRealmAdmin("master");

        verify(users, never()).save(any(UserCredentials.class));
        verify(roles, never()).save(any(UserRoles.class));
        verify(userRoles, never()).save(any(UserInRole.class));
    }

    @Test
    void existingUserMissingRoleAssignment_getsAssignedWithoutRecreatingUser() {
        when(tenants.findById("master")).thenReturn(Optional.of(new Tenant()));
        when(roles.findByTenantIdAndName("master", "admin")).thenReturn(Optional.of(new UserRoles("admin", "master")));
        final UserCredentials existing = new UserCredentials(); existing.setUserId("uid-master"); existing.setUsername("admin");
        when(users.findByUsername("admin")).thenReturn(Optional.of(existing));
        when(links.findByTenantIdAndUserId("master", "uid-master")).thenReturn(Optional.of(link("master", "uid-master")));
        when(userRoles.findByRoleIdAndUserId(any(), any())).thenReturn(Optional.empty());

        service.ensureRealmAdmin("master");

        verify(users, never()).save(any(UserCredentials.class));
        verify(userRoles).save(any(UserInRole.class));
    }
}
