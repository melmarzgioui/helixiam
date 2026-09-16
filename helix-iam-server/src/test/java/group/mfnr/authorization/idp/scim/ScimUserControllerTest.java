package group.mfnr.authorization.idp.scim;

import group.mfnr.authorization.amqp.user.UserAdminDto;
import group.mfnr.authorization.amqp.user.UserAdminPublisher;
import group.mfnr.authorization.amqp.user.UserWriteDto;
import group.mfnr.authorization.idp.provisioning.ProvisioningAdminPublisher;
import group.mfnr.authorization.idp.provisioning.ScimTokenCheck;
import group.mfnr.authorization.security.realm.RealmContextHolder;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Helix IAM E7 (SCIM 2.0): the Users provisioning endpoint — Bearer-token authn (reject without a token /
 * with a bad token), create mapping over the user-admin AMQP path, list + {@code userName eq} filtering.
 * Every response is a {@link ResponseEntity} (never a thrown exception → no /error 302).
 */
class ScimUserControllerTest {

    private final UserAdminPublisher users = mock(UserAdminPublisher.class);
    private final ProvisioningAdminPublisher provisioning = mock(ProvisioningAdminPublisher.class);
    private final ScimUserController controller = new ScimUserController(users, provisioning);

    @BeforeEach
    void bindRealmAndRequestContext() {
        RealmContextHolder.set("gov");
    }

    @AfterEach
    void clear() {
        RealmContextHolder.clear();
        RequestContextHolder.resetRequestAttributes();
    }

    private MockHttpServletRequest withBearer(final String token) {
        final MockHttpServletRequest request = new MockHttpServletRequest();
        request.setContextPath("/realms/gov");
        if (token != null) {
            request.addHeader("Authorization", "Bearer " + token);
        }
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));
        return request;
    }

    @Test
    void rejectsWithoutToken_401_andNeverTouchesTheUserStore() {
        final MockHttpServletRequest request = withBearer(null);

        final ResponseEntity<?> response = controller.list(null, null, null, request);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(response.getBody()).isInstanceOf(ScimError.class);
        assertThat(((ScimError) response.getBody()).schemas()).containsExactly(ScimSchemas.ERROR);
        verify(users, never()).list(any());
    }

    @Test
    void rejectsWithInvalidToken_401() {
        final MockHttpServletRequest request = withBearer("nope");
        when(provisioning.verifyScimToken(new ScimTokenCheck("gov", "nope"))).thenReturn(false);

        final ResponseEntity<?> response = controller.list(null, null, null, request);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        verify(users, never()).list(any());
    }

    @Test
    void create_mapsScimUserOntoUserAdminPath_andReturns201() {
        final MockHttpServletRequest request = withBearer("good");
        when(provisioning.verifyScimToken(new ScimTokenCheck("gov", "good"))).thenReturn(true);
        when(users.create(any())).thenReturn(new UserAdminDto("gov", "uid-9", "jdoe", "jane@example.com", true,
                false, false, List.of(), Map.of(ScimMapper.ATTR_GIVEN_NAME, "Jane"), 0L));

        final ScimUser body = new ScimUser(List.of(ScimSchemas.USER), null, "jdoe",
                new ScimUser.Name("Jane", "Doe", null),
                List.of(new ScimUser.Email("jane@example.com", "work", true)), true, null, null);

        final ResponseEntity<?> response = controller.create(body, request);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.CREATED);
        assertThat(response.getBody()).isInstanceOf(ScimUser.class);
        assertThat(((ScimUser) response.getBody()).id()).isEqualTo("uid-9");

        final var captor = org.mockito.ArgumentCaptor.forClass(UserWriteDto.class);
        verify(users).create(captor.capture());
        assertThat(captor.getValue().username()).isEqualTo("jdoe");
        assertThat(captor.getValue().email()).isEqualTo("jane@example.com");
        assertThat(captor.getValue().enabled()).isTrue();
    }

    @Test
    void create_rejectsMissingUserName_400() {
        final MockHttpServletRequest request = withBearer("good");
        when(provisioning.verifyScimToken(new ScimTokenCheck("gov", "good"))).thenReturn(true);

        final ScimUser body = new ScimUser(List.of(ScimSchemas.USER), null, null, null, null, null, null, null);

        final ResponseEntity<?> response = controller.create(body, request);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        verify(users, never()).create(any());
    }

    @Test
    void list_appliesUserNameEqFilter_andWrapsInListResponse() {
        final MockHttpServletRequest request = withBearer("good");
        when(provisioning.verifyScimToken(new ScimTokenCheck("gov", "good"))).thenReturn(true);
        when(users.list("gov")).thenReturn(List.of(
                new UserAdminDto("gov", "1", "alice", "a@e.com", true, false, false, List.of(), Map.of(), 0L),
                new UserAdminDto("gov", "2", "bob", "b@e.com", true, false, false, List.of(), Map.of(), 0L)));

        final ResponseEntity<?> response = controller.list("userName eq \"bob\"", null, null, request);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        @SuppressWarnings("unchecked")
        final ScimListResponse<ScimUser> list = (ScimListResponse<ScimUser>) response.getBody();
        assertThat(list.totalResults()).isEqualTo(1);
        assertThat(list.startIndex()).isEqualTo(1);
        assertThat(list.Resources()).singleElement().satisfies(u -> assertThat(u.userName()).isEqualTo("bob"));
        assertThat(list.schemas()).containsExactly(ScimSchemas.LIST_RESPONSE);
    }
}
