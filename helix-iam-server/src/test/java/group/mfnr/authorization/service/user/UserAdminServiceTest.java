package group.mfnr.authorization.service.user;

import group.mfnr.authorization.domain.tenant.Tenant;
import group.mfnr.authorization.domain.tenant.TenantUser;
import group.mfnr.authorization.domain.user.UserCredentials;
import group.mfnr.authorization.domain.user.UserRoles;
import group.mfnr.authorization.domain.user.admin.UserAdminDto;
import group.mfnr.authorization.domain.user.admin.UserPasswordDto;
import group.mfnr.authorization.domain.user.admin.UserWriteDto;
import group.mfnr.authorization.repository.UserCredentialsRepository;
import group.mfnr.authorization.repository.tenant.TenantRepository;
import group.mfnr.authorization.repository.tenant.TenantUserRepository;
import group.mfnr.authorization.service.PasswordEncoderService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Helix IAM E8.5: realm-scoped user administration over the global user store + tenant link.
 */
class UserAdminServiceTest {

    private TenantUserRepository tenantUserRepository;
    private TenantRepository tenantRepository;
    private UserCredentialsRepository userCredentialsRepository;
    private PasswordEncoderService passwordEncoderService;
    private UserAdminService service;

    @BeforeEach
    void setUp() {
        tenantUserRepository = mock(TenantUserRepository.class);
        tenantRepository = mock(TenantRepository.class);
        userCredentialsRepository = mock(UserCredentialsRepository.class);
        passwordEncoderService = mock(PasswordEncoderService.class);
        service = new UserAdminService(tenantUserRepository, tenantRepository, userCredentialsRepository, passwordEncoderService);
    }

    @Test
    void list_returnsRealmUsers_mappedWithRolesAttributesAndEnabledFlag() {
        final UserCredentials user = user("u-1", "alice@example.com", false, false, false);
        user.getUserAttributes().put("department", "Tax");
        final TenantUser link = tenantUser("gov", "u-1", new UserRoles("auditor", "gov"));

        when(tenantUserRepository.findAllByTenantId("gov")).thenReturn(List.of(link));
        when(userCredentialsRepository.findByUserId("u-1")).thenReturn(Optional.of(user));

        final List<UserAdminDto> users = service.list("gov");

        assertEquals(1, users.size());
        final UserAdminDto dto = users.get(0);
        assertEquals("alice@example.com", dto.username());
        assertTrue(dto.enabled(), "an un-disabled account is enabled");
        assertFalse(dto.locked());
        assertEquals(List.of("auditor"), dto.roles());
        assertEquals("Tax", dto.attributes().get("department"));
    }

    @Test
    void create_lowercasesUsername_encodesPassword_andLinksTenant() {
        when(passwordEncoderService.encode("s3cret")).thenReturn("$argon2id$hash");
        when(userCredentialsRepository.save(any(UserCredentials.class))).thenAnswer(inv -> {
            final UserCredentials u = inv.getArgument(0);
            u.setUserId("u-new");
            return u;
        });

        final UserWriteDto write = new UserWriteDto("gov", null, "Bob@Example.com", "Bob@Example.com", "s3cret",
                true, false, Map.of("team", "Finance"));
        final UserAdminDto created = service.create(write);

        final ArgumentCaptor<UserCredentials> userCaptor = ArgumentCaptor.forClass(UserCredentials.class);
        verify(userCredentialsRepository).save(userCaptor.capture());
        final UserCredentials saved = userCaptor.getValue();
        assertEquals("bob@example.com", saved.getUsername(), "username is normalised to lowercase");
        assertEquals("bob@example.com", saved.getEmail(), "email is normalised to lowercase");
        assertEquals("$argon2id$hash", saved.getPassword(), "password is Argon2id-encoded, never stored raw");
        assertFalse(saved.isDisabled());

        final ArgumentCaptor<TenantUser> linkCaptor = ArgumentCaptor.forClass(TenantUser.class);
        verify(tenantUserRepository).save(linkCaptor.capture());
        assertEquals("gov", linkCaptor.getValue().getTenantId());
        assertEquals("u-new", linkCaptor.getValue().getUserId());

        assertEquals("bob@example.com", created.username());
        assertEquals("bob@example.com", created.email(), "email is surfaced back in the admin DTO");
        assertTrue(created.enabled());
    }

    @Test
    void update_togglesEnabledAndLocked_andReplacesAttributes() {
        final UserCredentials user = user("u-1", "alice@example.com", false, false, false);
        user.getUserAttributes().put("old", "value");
        when(userCredentialsRepository.findByUserId("u-1")).thenReturn(Optional.of(user));
        when(tenantUserRepository.findByTenantIdAndUserId("gov", "u-1"))
                .thenReturn(Optional.of(tenantUser("gov", "u-1")));
        when(userCredentialsRepository.save(any(UserCredentials.class))).thenAnswer(inv -> inv.getArgument(0));

        service.update(new UserWriteDto("gov", "u-1", "alice@example.com", "Alice@New.com", null, false, true,
                Map.of("new", "attr")));

        assertTrue(user.isDisabled(), "enabled=false disables the account");
        assertTrue(user.isLocked());
        assertEquals("alice@new.com", user.getEmail(), "email is updated and lowercased");
        assertEquals(Map.of("new", "attr"), user.getUserAttributes(), "attributes are replaced, not merged");
    }

    @Test
    void resetPassword_encodesAndSaves_whenPresent_falseWhenAbsent() {
        final UserCredentials user = user("u-1", "alice@example.com", false, false, false);
        when(userCredentialsRepository.findByUserId("u-1")).thenReturn(Optional.of(user));
        when(userCredentialsRepository.findByUserId("ghost")).thenReturn(Optional.empty());
        when(passwordEncoderService.encode("newpass")).thenReturn("$argon2id$new");
        when(userCredentialsRepository.save(any(UserCredentials.class))).thenAnswer(inv -> inv.getArgument(0));

        assertTrue(service.resetPassword(new UserPasswordDto("gov", "u-1", "newpass")));
        assertEquals("$argon2id$new", user.getPassword());

        assertFalse(service.resetPassword(new UserPasswordDto("gov", "ghost", "x")));
    }

    @Test
    void create_rejectsBlankUsername() {
        final UserWriteDto write = new UserWriteDto("gov", null, "  ", "x@y.com", "s3cret",
                true, false, Map.of());
        final IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, () -> service.create(write));
        assertEquals("Username is required.", ex.getMessage());
        verify(userCredentialsRepository, never()).save(any());
    }

    @Test
    void create_withoutPassword_createsCredentiallessUser_withUpdatePasswordRequiredAction() {
        when(userCredentialsRepository.save(any(UserCredentials.class))).thenAnswer(inv -> {
            final UserCredentials u = inv.getArgument(0);
            u.setUserId("u-new");
            return u;
        });

        // Config-as-code import carries a user's profile but never a credential.
        final UserWriteDto write = new UserWriteDto("gov", null, "alice", "alice@gov.example", null,
                true, false, Map.of());
        final UserAdminDto created = service.create(write);

        final ArgumentCaptor<UserCredentials> userCaptor = ArgumentCaptor.forClass(UserCredentials.class);
        verify(userCredentialsRepository).save(userCaptor.capture());
        final UserCredentials saved = userCaptor.getValue();
        assertEquals("alice", saved.getUsername());
        assertNull(saved.getPassword(), "no password is stored for a credential-less import");
        assertTrue(saved.getRequiredActions() != null && saved.getRequiredActions().contains("UPDATE_PASSWORD"),
                "the user must set a password before first login");
        verify(passwordEncoderService, never()).encode(any());
        verify(tenantUserRepository).save(any(TenantUser.class));
        assertTrue(created.enabled());
    }

    @Test
    void resetPassword_rejectsBlankNewPassword() {
        final IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
                () -> service.resetPassword(new UserPasswordDto("gov", "u-1", "  ")));
        assertEquals("New password is required.", ex.getMessage());
        verify(userCredentialsRepository, never()).save(any());
    }

    private static UserCredentials user(final String id, final String username, final boolean disabled,
                                        final boolean locked, final boolean mfa) {
        final UserCredentials u = new UserCredentials();
        u.setUserId(id);
        u.setUsername(username);
        u.setDisabled(disabled);
        u.setAccountLocked(locked);
        u.setMfaEnabled(mfa);
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
