/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.security;

import io.helixiam.authorization.amqp.AuthFlowPublisher;
import io.helixiam.authorization.flow.FlowExecutor;
import io.helixiam.authorization.flow.persistence.AuthFlowMapper;
import io.helixiam.authorization.security.flow.FlowLoginSuccessHandler;
import io.helixiam.authorization.security.flow.ResolveSavedRequestRedirect;
import io.helixiam.authorization.security.oidc.PromptAndMaxAgeAuthorizeFilter;
import io.helixiam.authorization.security.session.AuthTimeStamper;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.web.context.SecurityContextHolderFilter;
import io.helixiam.authorization.security.mfa.MfaAuthenticationCodeVerifier;
import io.helixiam.authorization.security.mfa.handler.MfaAuthenticationSuccessHandler;
import io.helixiam.authorization.security.mfa.manager.MfaAuthorizationManager;
import io.helixiam.authorization.security.mfa.totp.TotpAuthenticationCodeVerifier;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcUserInfoAuthenticationContext;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcUserInfoAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;
import org.springframework.web.cors.CorsConfigurationSource;

import java.util.function.Function;

@Configuration
@Order(Ordered.HIGHEST_PRECEDENCE)
@EnableWebSecurity
// Security review M1: without this, every @PreAuthorize/@PostAuthorize in the codebase is SILENTLY
// IGNORED — a dangerous property for an IAM product, because a future method-level guard would look
// enforced while doing nothing. Enabling it makes method security actually apply.
@EnableMethodSecurity
public class SecurityConfig {

    private final String[] whitelist;
    private final boolean mfaEnabled;
    private final String spBaseUrl;
    private final boolean flowEngineEnabled;
    private final boolean adminDevOpen;
    private final boolean cookieSecure;
    private final boolean prometheusAnonymous;
    private final boolean springdocPublic;

    public SecurityConfig(@Value("${helix.security.whitelist:}") final String[] whitelist, @Value("${mfa.enabled:true}") boolean mfaEnabled, @Value("${sp.base.url:}") final String spBaseUrl,
                          @Value("${helix.flow-engine.enabled:false}") final boolean flowEngineEnabled,
                          @Value("${helix.admin.dev-open:false}") final boolean adminDevOpen,
                          // Security review M5: the XSRF-TOKEN cookie's Secure flag, sharing ONE knob with the
                          // session cookie (application.properties → server.servlet.session.cookie.secure).
                          // Secure by default; application-dev.properties flips it off for plain-HTTP localhost.
                          @Value("${helix.security.cookie-secure:true}") final boolean cookieSecure,
                          // Security review L2: whether /actuator/prometheus is reachable anonymously.
                          @Value("${helix.actuator.prometheus-anonymous:true}") final boolean prometheusAnonymous,
                          // Security review L3: whether the OpenAPI document / Swagger UI are anonymous.
                          @Value("${helix.springdoc.public:false}") final boolean springdocPublic) {
        this.whitelist = whitelist;
        this.mfaEnabled = mfaEnabled;
        this.spBaseUrl = spBaseUrl;
        this.adminDevOpen = adminDevOpen;
        this.flowEngineEnabled = flowEngineEnabled;
        this.cookieSecure = cookieSecure;
        this.prometheusAnonymous = prometheusAnonymous;
        this.springdocPublic = springdocPublic;
    }

    @Bean
    @Order(1)
    public SecurityFilterChain authorizationServerSecurityFilterChain(final HttpSecurity http, @Qualifier("helixClientCors") final CorsConfigurationSource corsConfigurationSource, final RegisteredClientRepository registeredClientRepository, final io.helixiam.authorization.security.realm.RealmSettingsResolver realmSettingsResolver, final org.springframework.security.core.session.SessionRegistry sessionRegistry, final io.helixiam.authorization.session.SsoLogoutResponseHandler ssoLogoutResponseHandler, final io.helixiam.authorization.amqp.resource.ResourceIndicatorPublisher resourceIndicatorPublisher, final org.springframework.security.oauth2.jwt.JwtEncoder helixJwtEncoder, final org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings authorizationServerSettings) throws Exception {
        // Helix IAM SSO P4: share OUR SessionRegistry bean with the authorization server BEFORE
        // applyDefaultSecurity (which would otherwise create its own). SAS reads it at token-issuance to
        // stamp the OIDC `sid` (session id hash) into id_tokens — the key that unifies a login's client
        // authorizations. The login chain (@Order 2) registers sessions into the same bean.
        http.setSharedObject(org.springframework.security.core.session.SessionRegistry.class, sessionRegistry);

        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);

        // Helix IAM SSO P2/P3: OIDC prompt/max_age + per-realm SSO max-lifetime (SAS has none). Anchored
        // right after the SecurityContext is loaded (so SecurityContextHolder is populated) and before the
        // SAS authorization endpoint, which runs later in the chain.
        http.addFilterAfter(new PromptAndMaxAgeAuthorizeFilter(registeredClientRepository, new AuthTimeStamper(), realmSettingsResolver),
                SecurityContextHolderFilter.class);

        // Helix IAM (#18, RFC 8707): validate the `resource` parameter at /oauth2/authorize + /oauth2/token
        // (absolute URI, no fragment, in the client's allow-list). No-op when no `resource` is present, so the
        // default OAuth flow is unchanged. Returns an invalid_target JSON error directly (not a /error redirect).
        http.addFilterAfter(new io.helixiam.authorization.security.resource.ResourceIndicatorAuthorizeFilter(resourceIndicatorPublisher),
                SecurityContextHolderFilter.class);

        // Helix IAM B11 (FAPI / RFC 9101 — JAR): validate/merge a signed Request Object on /oauth2/authorize,
        // and reject a plain request when the client requires a signed one. No-op for clients that neither
        // require nor send a `request` object, so the default authorize flow is unchanged.
        http.addFilterAfter(new io.helixiam.authorization.security.fapi.RequestObjectAuthorizeFilter(registeredClientRepository),
                SecurityContextHolderFilter.class);

        // Helix IAM B11 (FAPI / JARM): when a client opts into a `.jwt` response mode, repackage the
        // authorization response into a signed JWT. Wraps only redirects to the client's registered
        // redirect URIs, so non-JARM clients are byte-identical.
        http.addFilterAfter(new io.helixiam.authorization.security.fapi.JarmResponseFilter(registeredClientRepository, helixJwtEncoder),
                SecurityContextHolderFilter.class);

        Function<OidcUserInfoAuthenticationContext, OidcUserInfo> userInfoMapper = context -> {
            final OidcUserInfoAuthenticationToken authentication = context.getAuthentication();
            final JwtAuthenticationToken principal = (JwtAuthenticationToken) authentication.getPrincipal();

            return new OidcUserInfo(principal.getToken().getClaims());
        };


        // CORS is enforced by the realm/client-aware standalone CorsFilter (RealmCorsFilterConfig) which runs
        // ahead of the security chains, so preflight + actual requests are handled uniformly for both chains.
        http.securityContext(securityContext -> securityContext.requireExplicitSave(false));

        http.getConfigurer(OAuth2AuthorizationServerConfigurer.class).oidc(
                oidc -> oidc
                        .userInfoEndpoint(userInfo -> userInfo.userInfoMapper(userInfoMapper))
                        // Helix IAM E11 (RFC 7591): advertise the realm's Dynamic Client Registration endpoint in
                        // the OIDC discovery document. The `issuer` claim SAS populates is the realm-prefixed
                        // {base}/realms/{realm}; the DCR endpoint is served under the same realm prefix, so
                        // registration_endpoint = {issuer}/connect/register. Additive — does not touch the token
                        // hot path.
                        .providerConfigurationEndpoint(providerConfig -> providerConfig
                                .providerConfigurationCustomizer(
                                        new io.helixiam.authorization.idp.dcr.OidcRegistrationEndpointCustomizer()
                                                // A2 (FAPI2): advertise PS256 alongside RS256 in the discovery doc.
                                                .andThen(new io.helixiam.authorization.security.fapi.FapiSigningMetadataCustomizer())))
                        // Helix IAM SSO P5: enable OIDC RP-initiated logout (end_session). SAS validates
                        // id_token_hint + post_logout_redirect_uri; our handler cascades — terminating the
                        // whole SSO session (removing the user's authorizations + HTTP session) and fanning
                        // out back-/front-channel logout (P6) — then redirects to the post-logout URI.
                        .logoutEndpoint(logout -> logout.logoutResponseHandler(ssoLogoutResponseHandler))
        );

        // Story 4 (CLI auth): RFC 8628 device authorization grant — headless / CLI login on machines with no
        // browser. The device POSTs to /oauth2/device_authorization for a device_code + user_code, shows the
        // user a URL ({issuer}/activate) + the short code; the human approves at /activate (behind login); the
        // CLI then polls /oauth2/token. The built-in kubedna-cli client requires no consent, so approval is
        // one click. Both endpoints are realm-prefixed via the virtual context path like the rest of SAS.
        http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
                // Helix-branded consent screen (replaces SAS's default page) for the code flow…
                .authorizationEndpoint(authorizationEndpoint -> authorizationEndpoint.consentPage("/oauth2/consent"))
                .deviceAuthorizationEndpoint(deviceAuthorizationEndpoint ->
                        deviceAuthorizationEndpoint.verificationUri("/activate"))
                // …and the device flow (which always confirms consent).
                .deviceVerificationEndpoint(deviceVerificationEndpoint ->
                        deviceVerificationEndpoint.consentPage("/oauth2/consent"))
                // SAS's built-in public-client converter only activates for a PKCE *token* request, so a public
                // client (kubedna-cli) cannot start the device flow with the defaults. Add the device-sample
                // converter+provider so a device_authorization request carrying only client_id authenticates.
                .clientAuthentication(clientAuthentication -> clientAuthentication
                        .authenticationConverter(new io.helixiam.authorization.security.device.DeviceClientAuthenticationConverter(
                                authorizationServerSettings.getDeviceAuthorizationEndpoint(),
                                authorizationServerSettings.getTokenEndpoint(),
                                // Also let a public (PKCE) client authenticate at the PAR endpoint (RFC 9126 / FAPI2).
                                authorizationServerSettings.getPushedAuthorizationRequestEndpoint()))
                        .authenticationProvider(new io.helixiam.authorization.security.device.DeviceClientAuthenticationProvider(
                                registeredClientRepository)));

        // Helix IAM E7.3 (RFC 9126 — Pushed Authorization Requests): enable the /oauth2/par endpoint. SAS
        // ships PAR DISABLED by default; without this the endpoint is never registered, so /oauth2/par falls
        // through to the login chain (302) and pushed_authorization_request_endpoint is absent from the
        // discovery/AS-metadata documents. Enabling the configurer registers the PAR filter (joining the AS
        // endpoints matcher) and advertises the endpoint. Additive — clients that never call PAR are unaffected.
        http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
                .pushedAuthorizationRequestEndpoint(Customizer.withDefaults());

        http.exceptionHandling(exceptions ->
            exceptions.defaultAuthenticationEntryPointFor(
                    new LoginUrlAuthenticationEntryPoint("/login"),
                    new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
            )
        )
        // Accept access tokens for User Info and/or Client Registration
        .oauth2ResourceServer(resourceServer -> resourceServer.jwt(Customizer.withDefaults()));

        return http.build();
    }

    @Bean
    @Order(2)
    public SecurityFilterChain defaultSecurityFilterChain(final HttpSecurity http, @Qualifier("helixClientCors") final CorsConfigurationSource corsConfigurationSource, final FlowExecutor flowExecutor, final AuthFlowPublisher authFlowPublisher, final AuthFlowMapper authFlowMapper, final io.helixiam.authorization.security.audit.AuditLog auditLog, final io.helixiam.authorization.security.realm.SessionPolicyApplier sessionPolicyApplier, final org.springframework.security.core.session.SessionRegistry sessionRegistry, final io.helixiam.authorization.security.realm.ConcurrentSessionLimiter concurrentSessionLimiter, final io.helixiam.authorization.security.adminrbac.AdminAuthorizationManager adminAuthorizationManager, final io.helixiam.authorization.observability.HelixMetrics helixMetrics, final io.helixiam.authorization.security.requiredactions.RequiredActionsGate requiredActionsGate) throws Exception {
        // Helix IAM SSO P4: register every login's session in the SessionRegistry (unlimited concurrency)
        // so the authorization server can resolve its `sid`. The registry tracks session ids regardless of
        // where the HttpSession itself is stored.
        http.sessionManagement(session -> session.maximumSessions(1000).maxSessionsPreventsLogin(false).sessionRegistry(sessionRegistry));
        // #322: the end-user account console is a session-cookie SPA, so its writes need a CSRF token but
        // can't read an HttpOnly session token. Use the JS-readable XSRF-TOKEN cookie (the standard SPA
        // pattern, like Keycloak): CookieCsrfTokenRepository.withHttpOnlyFalse() + a plain request handler
        // (raw token in cookie and X-XSRF-TOKEN header — no per-request BREACH masking, matching Keycloak),
        // plus a filter that materialises the token so the cookie is written on the SPA's first (GET) call.
        // Server-rendered forms (login, MFA, flow) keep working: they render ${_csrf} into a hidden field.
        http.csrf(csrf -> csrf
                .csrfTokenRepository(csrfTokenRepository())
                .csrfTokenRequestHandler(new org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler()));
        http.addFilterAfter(new CsrfCookieFilter(), org.springframework.security.web.csrf.CsrfFilter.class);
        http.authorizeHttpRequests(requests -> requests.requestMatchers(whitelist).permitAll());
        // Helix IAM E4.2: the QR-login endpoints are reached by the unauthenticated enrolled phone
        // (confirm) and the mid-login browser (SSE/poll); they are secured by the device signature
        // + single-use rotating token, not the session, so permit them and exempt them from CSRF.
        http.authorizeHttpRequests(requests -> requests.requestMatchers("/qr/**", "/push/**").permitAll());
        http.csrf(csrf -> csrf.ignoringRequestMatchers("/qr/**", "/push/**"));
        // E4.4: only the phone's WYSIWYS sign sub-path is anonymous (secured by the device signature
        // over the canonical challenge); create/status/consume stay behind the initiator's session.
        http.authorizeHttpRequests(requests -> requests.requestMatchers("/tx/*/sign").permitAll());
        http.csrf(csrf -> csrf.ignoringRequestMatchers("/tx/*/sign"));
        // E4.1 enrollment: the phone redeems a ticket at exactly /device/enroll (anonymous, secured by
        // the single-use ticket + attestation). /device/enroll/start stays behind the user's session.
        http.authorizeHttpRequests(requests -> requests.requestMatchers("/device/enroll").permitAll());
        http.csrf(csrf -> csrf.ignoringRequestMatchers("/device/enroll"));
        // Helix IAM E5.3: the federation broker endpoints are part of the (anonymous) login path —
        // /broker/{alias} starts external login and /broker/{alias}/callback receives the IdP's
        // response. The callback is protected by the per-login anti-forgery state + the provider's
        // signature/nonce checks, not the session CSRF token, and the SAML POST binding arrives
        // cross-site from the IdP, so permit them and exempt the callback from CSRF.
        http.authorizeHttpRequests(requests -> requests.requestMatchers("/broker/**").permitAll());
        http.csrf(csrf -> csrf.ignoringRequestMatchers("/broker/*/callback"));
        // Helix IAM E7.1: SAML IdP role — metadata is public; the SSO endpoint stays behind login (an
        // unauthenticated SP request is sent through the flow engine first) and is CSRF-exempt because
        // the SP POSTs the AuthnRequest cross-site.
        http.authorizeHttpRequests(requests -> requests.requestMatchers("/saml/idp/metadata").permitAll());
        http.csrf(csrf -> csrf.ignoringRequestMatchers("/saml/idp/sso"));
        // SSO P8: SAML IdP Single Logout — the SP POSTs a signed LogoutRequest cross-site; it carries its own
        // signature so it doesn't need a CSRF token, and it's permitted so an already-logged-out browser can
        // still complete the logout handshake.
        http.authorizeHttpRequests(requests -> requests.requestMatchers("/saml/idp/slo").permitAll());
        http.csrf(csrf -> csrf.ignoringRequestMatchers("/saml/idp/slo"));
        // Helix IAM WIF: the Workload Identity Federation token-exchange endpoint is a machine-to-machine
        // OAuth endpoint authenticated entirely by the presented, cryptographically-verified workload JWT —
        // no session, no client secret. Permit it and exempt it from CSRF (non-browser cross-site POST).
        // Flat path because RealmRoutingFilter strips the /realms/{realm} prefix before security runs.
        http.authorizeHttpRequests(requests -> requests.requestMatchers("/workload-identity/token", "/agent/delegation/token").permitAll());
        http.csrf(csrf -> csrf.ignoringRequestMatchers("/workload-identity/token", "/agent/delegation/token"));
        // Helix IAM E11: SCIM 2.0 inbound provisioning (/scim/v2/**) and OIDC Dynamic Client Registration
        // (/connect/register**) are machine-to-machine APIs authenticated by their OWN per-realm bearer token
        // (SCIM token / initial-access-token / registration_access_token), verified in the controllers — not by
        // the session. So permit them here and exempt them from CSRF (they are non-browser, cross-site POSTs).
        // Paths are flat because RealmRoutingFilter strips the /realms/{realm} prefix before security runs.
        http.authorizeHttpRequests(requests -> requests.requestMatchers("/scim/v2/**", "/connect/register/**", "/connect/register").permitAll());
        http.csrf(csrf -> csrf.ignoringRequestMatchers("/scim/v2/**", "/connect/register/**", "/connect/register"));
        // Agent Phase C (MCP auth): RFC 9728 Protected Resource Metadata is public discovery, like OIDC discovery.
        http.authorizeHttpRequests(requests -> requests.requestMatchers("/.well-known/oauth-protected-resource").permitAll());
        http.authorizeHttpRequests(authorizationManagerRequestMatcherRegistry -> authorizationManagerRequestMatcherRegistry
                .requestMatchers("/mfa/totp", "/mfa/enable", "/flow", "/flow/**",
                        "/required-actions", "/required-actions/**").access(new MfaAuthorizationManager()));
        // Helix IAM E8.2: LOCAL-DEV ONLY (helix.admin.dev-open=true, default false) — open the admin
        // identity-provider API so the helix-admin console (served from a Vite dev proxy on a different
        // origin) can manage connections without the full OIDC/session wiring. NEVER enable in prod;
        // the durable path is a proper admin login + role-gated /admin/**.
        if (adminDevOpen) {
            // LOCAL-DEV ONLY: open the admin API for the cross-origin console. The RBAC manager would no-op
            // here anyway (dev-open short-circuits it), so permitAll keeps the e2e path byte-identical.
            http.authorizeHttpRequests(requests -> requests.requestMatchers("/admin/**").permitAll());
            http.csrf(csrf -> csrf.ignoringRequestMatchers("/admin/**"));
        } else {
            // Helix IAM (#19): fine-grained admin RBAC — an authenticated admin reaches a route group only if
            // their realm roles grant the matching admin permission. Default-safe: a realm with no grant model
            // configured behaves exactly as before (realm-admin/all). The manager requires authentication, so
            // /admin/** is never anonymous in production.
            http.authorizeHttpRequests(requests -> requests.requestMatchers("/admin/**").access(adminAuthorizationManager));
        }
        // Wave 3 observability: the health probe stays anonymous unconditionally — it is the container
        // liveness/readiness endpoint and must answer before anything can authenticate.
        // Security review L2: /actuator/info is NO LONGER anonymous (and is no longer exposed at all, see
        // management.endpoints.web.exposure.include) — it discloses build/git metadata for no benefit here.
        http.authorizeHttpRequests(requests -> requests.requestMatchers("/actuator/health", "/actuator/health/**").permitAll());
        // Security review L2: /actuator/prometheus anonymity is now an explicit, deliberate switch rather
        // than an accident of the allowlist. It stays anonymous BY DEFAULT so in-cluster scraping is
        // unchanged — restrict the scrape path with a NetworkPolicy / ingress rule. Set
        // helix.actuator.prometheus-anonymous=false to push it behind the authenticated gate instead.
        if (prometheusAnonymous) {
            http.authorizeHttpRequests(requests -> requests.requestMatchers("/actuator/prometheus").permitAll());
        }
        http.csrf(csrf -> csrf.ignoringRequestMatchers("/actuator/**"));
        // Wave 3: Swagger UI + OpenAPI JSON for the /admin/** API (GET-only docs).
        // Security review L3: the OpenAPI document is a complete map of the admin API, so it is NOT
        // anonymous by default. With helix.springdoc.public=false (production default) these paths fall
        // through to anyRequest().authenticated(); application-dev.properties sets it true.
        if (springdocPublic) {
            http.authorizeHttpRequests(requests -> requests.requestMatchers("/swagger-ui.html", "/swagger-ui/**", "/v3/api-docs", "/v3/api-docs/**").permitAll());
        }
        http.csrf(csrf -> csrf.ignoringRequestMatchers("/v3/api-docs/**"));
        http.authorizeHttpRequests(requests -> requests.anyRequest().authenticated());

        // Helix IAM E2.4: when the flow engine is enabled, the post-password steps are driven
        // by the data-driven engine instead of the hard-coded MFA routing. Default off, so the
        // live login path is unchanged unless helix.flow-engine.enabled=true.
        final FlowLoginSuccessHandler flowSuccessHandler = new FlowLoginSuccessHandler(flowExecutor, authFlowPublisher, authFlowMapper, spBaseUrl, sessionPolicyApplier, concurrentSessionLimiter);
        // SSO P1: resume the originating /oauth2/authorize after login (else the code comes back for the
        // dashboard, not the client that started the flow). Falls back to spBaseUrl when nothing is saved.
        final ResolveSavedRequestRedirect savedRequestRedirect = new ResolveSavedRequestRedirect();
        // SSO P2: stamp auth_time when the password-only login completes (no MFA/flow gate).
        final AuthTimeStamper authTimeStamper = new AuthTimeStamper();

        http.securityContext(securityContext -> securityContext.requireExplicitSave(false));
        http.formLogin(form -> form
            .loginPage("/login") //url to login page
            .successHandler((request, response, authentication) -> {
                // Helix IAM E8.5 (Events): audit the password-factor success that begins this login.
                // Prefer the typed username (human-readable + matches the LOGIN_FAILURE actor) over the
                // resolved principal name, which is the user's opaque id.
                final String successActor = request.getParameter("username") != null
                        ? request.getParameter("username") : authentication.getName();
                auditLog.emit(io.helixiam.authorization.security.audit.AuditEvent.authn(
                        io.helixiam.authorization.security.audit.AuditContext.nowIso(), "LOGIN_SUCCESS",
                        io.helixiam.authorization.security.realm.RealmContextHolder.get(),
                        successActor,
                        io.helixiam.authorization.security.audit.AuditContext.clientIp(request), "SUCCESS", null));
                helixMetrics.recordLogin(io.helixiam.authorization.security.realm.RealmContextHolder.get(), "success");
                // B1: if the user has pending required actions, hold them here and route to /required-actions
                // before any flow/MFA/redirect runs (the completion flow hands the auth back to this routing).
                if (requiredActionsGate.intercept(request, response, authentication)) {
                    return;
                }
                if (flowEngineEnabled) {
                    flowSuccessHandler.onAuthenticationSuccess(request, response, authentication);
                } else if(mfaEnabled) {
                    new MfaAuthenticationSuccessHandler("/mfa/totp", "/mfa/enable").onAuthenticationSuccess(request, response, authentication);
                } else {
                    authTimeStamper.stamp(request); // SSO P2: record auth_time for max_age/prompt
                    sessionPolicyApplier.applyOnLogin(request, io.helixiam.authorization.security.realm.RealmContextHolder.get()); // SSO P3
                    savedRequestRedirect.sendRedirect(request, response, spBaseUrl);
                }
            })
            .failureHandler( //and when it fails
                (req, res, ex) -> {
                    // Helix IAM E8.5 (Events): audit the failed login attempt for the SIEM.
                    auditLog.emit(io.helixiam.authorization.security.audit.AuditEvent.authn(
                            io.helixiam.authorization.security.audit.AuditContext.nowIso(), "LOGIN_FAILURE",
                            io.helixiam.authorization.security.realm.RealmContextHolder.get(),
                            req.getParameter("username") != null ? req.getParameter("username") : io.helixiam.authorization.security.audit.AuditContext.ANONYMOUS,
                            io.helixiam.authorization.security.audit.AuditContext.clientIp(req), "FAILURE",
                            java.util.Map.of("reason", ex.getClass().getSimpleName())));
                    helixMetrics.recordLogin(io.helixiam.authorization.security.realm.RealmContextHolder.get(), "failure");
                    // Context-relative so the redirect stays under the realm's virtual context path
                    // (/realms/{realm}/login); a bare "/login" would be container-root-relative.
                    if(ex instanceof LockedException) {
                        res.sendRedirect(req.getContextPath() + "/login?error=accountLocked");
                    } else {
                        res.sendRedirect(req.getContextPath() + "/login?error=error");
                    }
                }
            )
        );

        // Session-expiry on an admin API call must surface as 401, NOT a 302 → /login. A browser fetch()
        // follows a login redirect transparently (returning the login HTML), or — when the redirect drops
        // to a different origin — dies with a network error; either way the SPA never learns the session
        // lapsed and just shows a dead "could not load". Returning 401 for /admin/** (API-only, never a page
        // navigation) lets the console's fetch wrapper detect it and send the browser to the login page.
        // Real page navigations (the login form, account console) still get the /login redirect from
        // form-login's default entry point.
        http.exceptionHandling(ex -> ex.defaultAuthenticationEntryPointFor(
                new org.springframework.security.web.authentication.HttpStatusEntryPoint(org.springframework.http.HttpStatus.UNAUTHORIZED),
                new org.springframework.security.web.util.matcher.AntPathRequestMatcher("/admin/**")));

        return http.build();
    }

    @Bean
    public MfaAuthenticationCodeVerifier twoFactorAuthenticationCodeVerifier() {
        return new TotpAuthenticationCodeVerifier();
    }

    /**
     * The {@code XSRF-TOKEN} cookie repository.
     *
     * <p>Security review M5: the cookie's {@code Secure} flag was previously left to the container, which
     * derives it from {@code request.isSecure()} — proxy-dependent, and behind a TLS-terminating ingress
     * without forwarded-header handling that evaluates to {@code false}, so the CSRF token was emitted over
     * a cookie the browser would happily also send in cleartext. It is now pinned from
     * {@code helix.security.cookie-secure} (default {@code true}, the same single knob as the session
     * cookie; {@code false} only in the dev profile).
     *
     * <p>{@code HttpOnly} deliberately stays <strong>false</strong>: the account/admin SPAs read this cookie
     * with JavaScript to echo it back in the {@code X-XSRF-TOKEN} header — that is the whole point of the
     * double-submit pattern, and flipping it would break every SPA write.
     */
    org.springframework.security.web.csrf.CookieCsrfTokenRepository csrfTokenRepository() {
        final org.springframework.security.web.csrf.CookieCsrfTokenRepository repository =
                org.springframework.security.web.csrf.CookieCsrfTokenRepository.withHttpOnlyFalse();
        repository.setCookieCustomizer(cookie -> cookie.secure(cookieSecure));
        return repository;
    }

    /**
     * #322: forces the deferred {@link org.springframework.security.web.csrf.CsrfToken} to be loaded on
     * every request so {@code CookieCsrfTokenRepository} writes the {@code XSRF-TOKEN} cookie — including on
     * the account SPA's safe (GET) calls, where the token is otherwise never accessed and thus never set.
     */
    static final class CsrfCookieFilter extends org.springframework.web.filter.OncePerRequestFilter {
        @Override
        protected void doFilterInternal(final jakarta.servlet.http.HttpServletRequest request,
                                        final jakarta.servlet.http.HttpServletResponse response,
                                        final jakarta.servlet.FilterChain filterChain)
                throws jakarta.servlet.ServletException, java.io.IOException {
            final org.springframework.security.web.csrf.CsrfToken csrfToken =
                    (org.springframework.security.web.csrf.CsrfToken) request.getAttribute(
                            org.springframework.security.web.csrf.CsrfToken.class.getName());
            if (csrfToken != null) {
                csrfToken.getToken(); // materialise → triggers the deferred cookie write
            }
            filterChain.doFilter(request, response);
        }
    }
}
