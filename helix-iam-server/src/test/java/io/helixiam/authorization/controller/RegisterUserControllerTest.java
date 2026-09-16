package io.helixiam.authorization.controller;

import io.helixiam.authorization.amqp.realm.RealmSettingsDto;
import io.helixiam.authorization.amqp.scope.ClaimDto;
import io.helixiam.authorization.amqp.scope.ClaimScopePublisher;
import io.helixiam.authorization.amqp.user.UserPublisher;
import io.helixiam.authorization.security.realm.RealmContextHolder;
import io.helixiam.authorization.security.realm.RealmSettingsResolver;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

class RegisterUserControllerTest {

    private UserPublisher userPublisher;
    private RealmSettingsResolver resolver;
    private ClaimScopePublisher claimScopePublisher;
    private BrandingSupport brandingSupport;
    private MockMvc mvc;

    private static RealmSettingsDto settings(final String realm, final boolean registrationEnabled, final String primary) {
        return new RealmSettingsDto(realm, realm, null, 3600, 5_184_000, false, false, 12, true,
                1800, 36000, false, 2_592_000,
                false, 5, 900, 900, false,
                false, false, false, false, false, 0,
                false, "none", null, null, 0, true,
                false, 40, 70, "allow", "step_up", "deny",
                null, primary, null, null, null,
                registrationEnabled);
    }

    @BeforeEach
    void setUp() {
        userPublisher = mock(UserPublisher.class);
        resolver = mock(RealmSettingsResolver.class);
        claimScopePublisher = mock(ClaimScopePublisher.class);
        brandingSupport = new BrandingSupport();               // real branding, mock resolver inside it
        ReflectionTestUtils.setField(brandingSupport, "realmSettingsResolver", resolver);

        final RegisterUserController controller = new RegisterUserController(userPublisher, true);
        ReflectionTestUtils.setField(controller, "realmSettingsResolver", resolver);
        ReflectionTestUtils.setField(controller, "claimScopePublisher", claimScopePublisher);
        ReflectionTestUtils.setField(controller, "brandingSupport", brandingSupport);
        mvc = MockMvcBuilders.standaloneSetup(controller).build();
        RealmContextHolder.set("acme");
    }

    @AfterEach
    void tearDown() {
        RealmContextHolder.clear();
    }

    @Test
    void get_enabledRealm_exposesClaimsAndBranding() throws Exception {
        when(resolver.get("acme")).thenReturn(settings("acme", true, "#123456"));
        when(claimScopePublisher.claims("acme")).thenReturn(List.of(
                new ClaimDto("acme", "c1", "given_name", "Given name", "Alice", true)));

        mvc.perform(get("/register"))
                .andExpect(view().name("register/register"))
                .andExpect(model().attribute("registerEnabled", true))
                .andExpect(model().attribute("brandingPrimaryColor", "#123456"))
                .andExpect(model().attributeExists("registrationClaims"));
    }

    @Test
    void get_disabledRealm_registerEnabledFalse() throws Exception {
        when(resolver.get("acme")).thenReturn(settings("acme", false, null));
        when(claimScopePublisher.claims("acme")).thenReturn(List.of());

        mvc.perform(get("/register"))
                .andExpect(model().attribute("registerEnabled", false));
    }

    @Test
    void post_missingMandatoryClaim_rejectsWithoutSignup() throws Exception {
        when(resolver.get("acme")).thenReturn(settings("acme", true, null));
        when(claimScopePublisher.claims("acme")).thenReturn(List.of(
                new ClaimDto("acme", "c1", "given_name", "Given name", "Alice", true)));

        mvc.perform(post("/register")
                        .param("username", "alice@acme.nl")
                        .param("password", "Sup3rSecret!")
                        .param("repeatPassword", "Sup3rSecret!")
                        .param("given_name", ""))            // mandatory but blank
                .andExpect(view().name("register/register"))
                .andExpect(model().attributeExists("errors"));
        verify(userPublisher, never()).selfSignup(any());
    }

    @Test
    void post_valid_harvestsClaimsAndSignsUp() throws Exception {
        when(resolver.get("acme")).thenReturn(settings("acme", true, null));
        when(claimScopePublisher.claims("acme")).thenReturn(List.of(
                new ClaimDto("acme", "c1", "given_name", "Given name", "Alice", true),
                new ClaimDto("acme", "c2", "department", "Department", "Sales", false)));

        mvc.perform(post("/register")
                        .param("username", "alice@acme.nl")
                        .param("password", "Sup3rSecret!")
                        .param("repeatPassword", "Sup3rSecret!")
                        .param("given_name", "Alice")
                        .param("department", "Sales"))
                .andExpect(view().name("register/success"));

        final ArgumentCaptor<io.helixiam.authorization.domain.UserRegister> captor =
                ArgumentCaptor.forClass(io.helixiam.authorization.domain.UserRegister.class);
        verify(userPublisher).selfSignup(captor.capture());
        assertThat(captor.getValue().getAttributes())
                .containsEntry("given_name", "Alice")
                .containsEntry("department", "Sales");
    }

    @Test
    void post_registrationDisabled_doesNotSignUp() throws Exception {
        when(resolver.get("acme")).thenReturn(settings("acme", false, null));
        when(claimScopePublisher.claims("acme")).thenReturn(List.of());

        mvc.perform(post("/register")
                        .param("username", "alice@acme.nl")
                        .param("password", "Sup3rSecret!")
                        .param("repeatPassword", "Sup3rSecret!"))
                .andExpect(view().name("register/register"));
        verify(userPublisher, never()).selfSignup(any());
    }
}
