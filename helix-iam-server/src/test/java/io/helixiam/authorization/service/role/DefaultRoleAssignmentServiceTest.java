package io.helixiam.authorization.service.role;

import io.helixiam.authorization.domain.user.UserInRole;
import io.helixiam.authorization.domain.user.UserRoles;
import io.helixiam.authorization.repository.UserInRoleRepository;
import io.helixiam.authorization.repository.UserRolesRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/** Helix IAM: new users auto-receive the realm's default role. */
class DefaultRoleAssignmentServiceTest {

    private UserRolesRepository roles;
    private UserInRoleRepository userInRole;
    private DefaultRoleAssignmentService service;

    @BeforeEach
    void setUp() {
        roles = mock(UserRolesRepository.class);
        userInRole = mock(UserInRoleRepository.class);
        service = new DefaultRoleAssignmentService(roles, userInRole);
    }

    @Test
    void assignsTheDefaultRoleToTheNewUser() {
        when(roles.findFirstByTenantIdAndDefaultRoleTrue("acme"))
                .thenReturn(Optional.of(new UserRoles("r-user", "user", "acme", true, true)));
        when(userInRole.findByRoleIdAndUserIdAndTenantUserId("r-user", "u1", "tu1")).thenReturn(Optional.empty());

        service.assignDefaultRole("acme", "u1", "tu1");

        final ArgumentCaptor<UserInRole> saved = ArgumentCaptor.forClass(UserInRole.class);
        verify(userInRole).save(saved.capture());
        assertEquals("r-user", saved.getValue().toString()); // toString() returns roleId
    }

    @Test
    void noOp_whenRealmHasNoDefaultRole() {
        when(roles.findFirstByTenantIdAndDefaultRoleTrue("acme")).thenReturn(Optional.empty());
        service.assignDefaultRole("acme", "u1", "tu1");
        verify(userInRole, never()).save(any());
    }

    @Test
    void doesNotDoubleAssign_whenAlreadyHeld() {
        when(roles.findFirstByTenantIdAndDefaultRoleTrue("acme"))
                .thenReturn(Optional.of(new UserRoles("r-user", "user", "acme", true, true)));
        when(userInRole.findByRoleIdAndUserIdAndTenantUserId("r-user", "u1", "tu1"))
                .thenReturn(Optional.of(new UserInRole("r-user", "u1", "tu1")));

        service.assignDefaultRole("acme", "u1", "tu1");

        verify(userInRole, never()).save(any());
    }
}
