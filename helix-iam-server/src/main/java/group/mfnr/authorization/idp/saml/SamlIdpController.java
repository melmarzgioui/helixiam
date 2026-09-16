package group.mfnr.authorization.idp.saml;

import group.mfnr.authorization.domain.UserCredentials;
import group.mfnr.authorization.security.realm.RealmContextHolder;
import group.mfnr.authorization.session.SsoLogoutService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

/**
 * Helix IAM E7.1: Helix's SAML2 IdP endpoints. {@code /saml/idp/sso} receives an SP AuthnRequest
 * (HTTP-Redirect GET or HTTP-POST), and — for the already-authenticated user (the endpoint sits
 * behind Helix login, so an unauthenticated request is sent through the flow engine first) — issues a
 * signed Response addressed to the registered SP's ACS, returned as an auto-submitting POST form.
 * {@code /saml/idp/metadata} publishes the IdP metadata. Active only when {@code helix.idp.saml.enabled=true}.
 */
@Controller
@ConditionalOnProperty(prefix = "helix.idp.saml", name = "enabled", havingValue = "true")
public class SamlIdpController {

    private static final Logger LOG = LogManager.getLogger(SamlIdpController.class);

    /** AuthnRequest ids we've already forced a re-auth for, so a ForceAuthn saved-request retry doesn't loop. */
    private static final java.util.Set<String> FORCED_REQUESTS = java.util.concurrent.ConcurrentHashMap.newKeySet();

    private final SamlIdpProperties properties;
    private final SamlAuthnRequestParser parser;
    private final SamlAssertionIssuer issuer;
    private final String idpBaseUrl;
    private final SamlLogoutRequestParser logoutRequestParser;
    private final SamlLogoutRequestIssuer logoutRequestIssuer;
    private final SamlLogoutResponseIssuer logoutResponseIssuer;
    private final SsoLogoutService ssoLogoutService;
    // Per-realm SAML signing material: each realm signs assertions with ITS OWN certificate, derived from
    // the realm's active signing key (the same key OIDC JWKS publishes). Replaces the single deployment-wide
    // helix.idp.saml.signing* config so a realm is a genuinely isolated IdP and key rotation rotates the cert.
    private final RealmSamlCredentialSource credentialSource;
    // Per-realm relying parties registered via the admin API + console, read fresh per request. The
    // static helix.idp.saml.relyingParties config is only a fallback (no store / store unreachable).
    private final SamlRelyingPartyConfigSource rpSource;
    // Application model: when the calling SP is linked to an Application, the SAML assertion releases the
    // SAME claim profile as the app's OIDC tokens (not just mail), resolved via the shared UserInfoService.
    private final group.mfnr.authorization.service.UserInfoService userInfoService;

    public SamlIdpController(final SamlIdpProperties properties, final SamlAuthnRequestParser parser,
                            final SamlAssertionIssuer issuer, @Value("${idp.base.url}") final String idpBaseUrl,
                            final SamlLogoutRequestParser logoutRequestParser,
                            final SamlLogoutRequestIssuer logoutRequestIssuer,
                            final SamlLogoutResponseIssuer logoutResponseIssuer,
                            final SsoLogoutService ssoLogoutService,
                            final RealmSamlCredentialSource credentialSource,
                            final SamlRelyingPartyConfigSource rpSource,
                            final group.mfnr.authorization.service.UserInfoService userInfoService) {
        this.properties = properties;
        this.parser = parser;
        this.issuer = issuer;
        this.idpBaseUrl = idpBaseUrl;
        this.logoutRequestParser = logoutRequestParser;
        this.logoutRequestIssuer = logoutRequestIssuer;
        this.logoutResponseIssuer = logoutResponseIssuer;
        this.ssoLogoutService = ssoLogoutService;
        this.credentialSource = credentialSource;
        this.rpSource = rpSource;
        this.userInfoService = userInfoService;
    }

    /**
     * Enforce the {@code helix.idp.saml.enabled} flag: when the SAML IdP role is switched off, every
     * {@code /saml/idp/*} endpoint behaves as if it doesn't exist (404) rather than silently serving.
     */
    private void requireSamlIdpEnabled() {
        if (!properties.isEnabled()) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "SAML IdP is disabled for this deployment");
        }
    }

    @GetMapping("/saml/idp/sso")
    public String ssoRedirect(@RequestParam(value = "SAMLRequest", required = false) final String samlRequest,
                              @RequestParam(value = "RelayState", required = false) final String relayState,
                              @RequestParam(value = "sp", required = false) final String spEntityId,
                              final HttpServletRequest http, final Model model) {
        requireSamlIdpEnabled();
        if ((samlRequest == null || samlRequest.isBlank()) && spEntityId != null && !spEntityId.isBlank()) {
            return idpInitiatedSso(spEntityId, relayState, SecurityContextHolder.getContext().getAuthentication(), model);
        }
        return processSso(samlRequest, relayState, true, SecurityContextHolder.getContext().getAuthentication(), model, http);
    }

    /**
     * WSO2-class IdP-initiated SSO: with no inbound AuthnRequest, push an unsolicited signed assertion to a
     * registered SP that has {@code idpInitiatedSsoEnabled}. The user must already be authenticated.
     */
    String idpInitiatedSso(final String spEntityId, final String relayState, final Authentication authentication,
                           final Model model) {
        if (authentication == null || !authentication.isAuthenticated()) {
            return "redirect:/login";
        }
        final SamlIdpProperties.RelyingParty rp = relyingParty(spEntityId);
        if (!rp.opts().idpInitiatedSsoEnabledOrDefault()) {
            throw new IllegalStateException("IdP-initiated SSO is not enabled for SP " + spEntityId);
        }
        final String acsUrl = rp.assertionConsumerServiceUrl();
        final String subjectNameId = subjectForFormat(authentication, rp.opts().nameIdFormatOrDefault());
        final Map<String, String> attributes = attributes(authentication, applicationIdForSp(spEntityId));
        final String response = issuer.issueResponse(credentialSource.current(), rp.entityId(), acsUrl,
                subjectNameId, attributes, rp.defaultAuthnContextClassRef(), null, rp.opts());
        LOG.info("SAML IdP: IdP-initiated assertion for {} to SP {}", subjectNameId, rp.entityId());
        return postBack(model, acsUrl, relayState, response);
    }

    @PostMapping("/saml/idp/sso")
    public String ssoPost(@RequestParam("SAMLRequest") final String samlRequest,
                          @RequestParam(value = "RelayState", required = false) final String relayState,
                          final Model model) {
        requireSamlIdpEnabled();
        return processSso(samlRequest, relayState, false, SecurityContextHolder.getContext().getAuthentication(), model, null);
    }

    /** Back-compat overload (no servlet request) — used by tests; redirect-binding signature check is skipped. */
    String processSso(final String samlRequest, final String relayState, final boolean redirectBinding,
                      final Authentication authentication, final Model model) {
        return processSso(samlRequest, relayState, redirectBinding, authentication, model, null);
    }

    String processSso(final String samlRequest, final String relayState, final boolean redirectBinding,
                      final Authentication authentication, final Model model, final HttpServletRequest http) {
        // Parse first so we can honour the AuthnRequest's protocol controls (ForceAuthn / IsPassive) even
        // before deciding whether to prompt for login.
        final SamlAuthnRequestParser.AuthnRequestInfo request = parser.parse(samlRequest, redirectBinding);
        final SamlIdpProperties.RelyingParty rp = relyingParty(request.spEntityId());

        // WSO2-class: when the SP requires signed AuthnRequests, its signature must verify (POST = embedded
        // XML signature; Redirect = signature over the raw query string). Gated per-SP, default off.
        if (rp.opts().wantAuthnRequestsSignedOrDefault()) {
            final boolean ok = redirectBinding
                    ? parser.isRedirectSignatureValid(http == null ? null : http.getQueryString(), rp.signingCertificate())
                    : parser.isPostSignatureValid(samlRequest, rp.signingCertificate());
            if (!ok) {
                throw new IllegalStateException("Invalid or missing AuthnRequest signature for SP " + rp.entityId());
            }
        }

        // WSO2-class: the requested ACS must be one the SP registered (default ACS + additional ACS URLs);
        // otherwise fall back to the registered default. Stops an attacker pointing the assertion elsewhere.
        final String acsUrl = resolveAcs(rp, request.assertionConsumerServiceUrl());

        final boolean authed = authentication != null && authentication.isAuthenticated();
        if (!authed) {
            if (request.isPassive()) {
                // IsPassive: never prompt — tell the SP we can't satisfy it without interaction.
                return postBack(model, acsUrl, relayState, issuer.issueStatusResponse(credentialSource.current(),
                        acsUrl, request.requestId(), "urn:oasis:names:tc:SAML:2.0:status:NoPassive"));
            }
            return "redirect:/login"; // flow engine authenticates, then the SP retries SSO (saved request)
        }
        // ForceAuthn: re-authenticate even with an active session. Guard with a per-request marker so the
        // SP's saved-request retry (same request id) doesn't loop forever.
        if (request.forceAuthn() && request.requestId() != null && FORCED_REQUESTS.add(request.requestId())) {
            SecurityContextHolder.clearContext();
            if (http != null) {
                final HttpSession session = http.getSession(false);
                if (session != null) {
                    session.invalidate();
                }
            }
            return "redirect:/login";
        }

        // RequestedAuthnContext: assert the SP's requested LoA when present, else the registered default.
        final String authnCtx = request.requestedAuthnContextClassRef() != null
                ? request.requestedAuthnContextClassRef() : rp.defaultAuthnContextClassRef();
        final String subjectNameId = subjectForFormat(authentication, rp.opts().nameIdFormatOrDefault());
        final Map<String, String> attributes = attributes(authentication, applicationIdForSp(request.spEntityId()));
        final String response = issuer.issueResponse(credentialSource.current(), rp.entityId(),
                acsUrl, subjectNameId, attributes, authnCtx, request.requestId(), rp.opts());

        LOG.info("SAML IdP: issued assertion for {} to SP {}", subjectNameId, rp.entityId());
        return postBack(model, acsUrl, relayState, response);
    }

    /** Render the auto-submitting POST form that delivers a SAMLResponse to an SP endpoint. */
    private static String postBack(final Model model, final String action, final String relayState, final String samlResponse) {
        final Map<String, String> fields = new HashMap<>();
        fields.put("SAMLResponse", samlResponse);
        if (relayState != null) {
            fields.put("RelayState", relayState);
        }
        model.addAttribute("action", action);
        model.addAttribute("fields", fields);
        return "flow/saml-post";
    }

    // --- SSO P8: SAML2 Single Logout (IdP SLO) ----------------------------------------------------

    @GetMapping("/saml/idp/slo")
    public String sloRedirect(@RequestParam("SAMLRequest") final String samlRequest,
                              @RequestParam(value = "RelayState", required = false) final String relayState,
                              final HttpServletRequest http, final Model model) {
        requireSamlIdpEnabled();
        return processSlo(samlRequest, relayState, true, http, model);
    }

    @PostMapping("/saml/idp/slo")
    public String sloPost(@RequestParam("SAMLRequest") final String samlRequest,
                          @RequestParam(value = "RelayState", required = false) final String relayState,
                          final HttpServletRequest http, final Model model) {
        requireSamlIdpEnabled();
        return processSlo(samlRequest, relayState, false, http, model);
    }

    /**
     * Handle an SP's {@code <LogoutRequest>}: validate it against the registered SP (and its signature when a
     * cert is configured), terminate the user's Helix session — cascading the OIDC Single Logout and ending the
     * IdP HTTP session — fan a signed LogoutRequest out to the other SAML SPs, then return a signed
     * {@code <LogoutResponse>} (Status=Success) to the requesting SP's SLO via an auto-submitting POST form.
     */
    String processSlo(final String samlRequest, final String relayState, final boolean redirectBinding,
                      final HttpServletRequest http, final Model model) {
        final SamlLogoutRequestParser.LogoutRequestInfo info = logoutRequestParser.parse(samlRequest, redirectBinding);
        final SamlIdpProperties.RelyingParty rp = relyingParty(info.spEntityId());

        // Security gate: if the SP registered a signing cert, its LogoutRequest signature must verify.
        if (rp.signingCertificate() != null && !rp.signingCertificate().isBlank()
                && !logoutRequestParser.isSignatureValid(samlRequest, redirectBinding, rp.signingCertificate())) {
            throw new IllegalStateException("Invalid SAML LogoutRequest signature for SP " + rp.entityId());
        }

        final String realm = RealmContextHolder.get() == null ? "master" : RealmContextHolder.get();
        // Cascade the OIDC Single Logout for this subject (best-effort — a pure-SAML user has no OAuth authzs).
        try {
            ssoLogoutService.terminate(info.nameId(), realm, idpBaseUrl + "/realms/" + realm);
        } catch (final RuntimeException e) {
            LOG.warn("SAML SLO: OIDC cascade for {} failed (continuing): {}", info.nameId(), e.getMessage());
        }
        // End the IdP (Helix) HTTP session so the user is logged out of the IdP itself.
        final HttpSession session = http == null ? null : http.getSession(false);
        if (session != null) {
            session.invalidate();
        }
        SecurityContextHolder.clearContext();

        // Fan a signed LogoutRequest out to every OTHER registered SAML SP that advertises an SLO endpoint.
        allRelyingParties().stream()
                .filter(other -> !other.entityId().equals(rp.entityId()))
                .filter(other -> other.singleLogoutServiceUrl() != null && !other.singleLogoutServiceUrl().isBlank())
                .forEach(other -> {
                    try {
                        logoutRequestIssuer.issueLogoutRequest(credentialSource.current(),
                                other.singleLogoutServiceUrl(), info.nameId());
                        LOG.info("SAML SLO: propagated logout for {} to SP {}", info.nameId(), other.entityId());
                    } catch (final RuntimeException e) {
                        LOG.warn("SAML SLO: could not propagate to SP {} (continuing): {}", other.entityId(), e.getMessage());
                    }
                });

        // Confirm to the requesting SP with a signed LogoutResponse on its SLO endpoint (ACS as a fallback).
        final String sloUrl = rp.singleLogoutServiceUrl() != null && !rp.singleLogoutServiceUrl().isBlank()
                ? rp.singleLogoutServiceUrl() : rp.assertionConsumerServiceUrl();
        final String response = logoutResponseIssuer.issueLogoutResponse(credentialSource.current(), sloUrl, info.requestId());

        final Map<String, String> fields = new HashMap<>();
        fields.put("SAMLResponse", response);
        if (relayState != null) {
            fields.put("RelayState", relayState);
        }
        model.addAttribute("action", sloUrl);
        model.addAttribute("fields", fields);
        LOG.info("SAML IdP: completed Single Logout for {} (requested by SP {})", info.nameId(), rp.entityId());
        return "flow/saml-post";
    }

    private SamlIdpProperties.RelyingParty relyingParty(final String spEntityId) {
        return allRelyingParties().stream()
                .filter(rp -> rp.entityId().equals(spEntityId))
                .findFirst()
                .orElseThrow(() -> new IllegalStateException("Unregistered SAML relying party: " + spEntityId));
    }

    /** The ACS to use: the requested one if it's registered (default + additional), else the default. */
    private static String resolveAcs(final SamlIdpProperties.RelyingParty rp, final String requestedAcs) {
        if (requestedAcs == null || requestedAcs.isBlank()) {
            return rp.assertionConsumerServiceUrl();
        }
        final java.util.Set<String> allowed = new java.util.HashSet<>();
        allowed.add(rp.assertionConsumerServiceUrl());
        allowed.addAll(rp.opts().additionalAcsUrlsOrEmpty());
        if (allowed.contains(requestedAcs)) {
            return requestedAcs;
        }
        throw new IllegalStateException("Requested ACS not registered for SP " + rp.entityId() + ": " + requestedAcs);
    }

    /**
     * Resolve the NameID value for the SP's requested format: {@code emailAddress} → the user's email,
     * {@code transient} → a one-time pseudonymous id, everything else ({@code persistent}/{@code unspecified})
     * → the stable authenticated subject (today's behaviour).
     */
    private String subjectForFormat(final Authentication authentication, final String nameIdFormat) {
        if (nameIdFormat == null) {
            return authentication.getName();
        }
        if (nameIdFormat.endsWith("nameid-format:emailAddress")) {
            try {
                final Map<String, String> claims = userInfoService.getOidcClaimProfile(authentication.getName());
                final String email = claims == null ? null : claims.get("email");
                if (email != null && !email.isBlank()) {
                    return email;
                }
            } catch (final RuntimeException e) {
                LOG.debug("SAML emailAddress NameID: no email for {}, using name", authentication.getName());
            }
        } else if (nameIdFormat.endsWith("nameid-format:transient")) {
            return "_t" + java.util.UUID.randomUUID();
        }
        return authentication.getName();
    }

    /**
     * The relying parties registered for the current realm: the persisted ones (admin API / console)
     * take precedence, with the static {@code helix.idp.saml.relyingParties} config merged in as a
     * fallback. Read fresh per request — SAML SSO/SLO is low-frequency, so a store round-trip is cheap
     * and always reflects the latest console change. Store failures degrade to the static config.
     */
    private java.util.List<SamlIdpProperties.RelyingParty> allRelyingParties() {
        final java.util.Map<String, SamlIdpProperties.RelyingParty> byEntityId = new java.util.LinkedHashMap<>();
        for (final SamlIdpProperties.RelyingParty rp : properties.getRelyingParties()) {
            byEntityId.put(rp.entityId(), rp);
        }
        try {
            final String realm = RealmContextHolder.get() == null ? "master" : RealmContextHolder.get();
            for (final var c : rpSource.load(realm)) {
                if (c.enabled()) {
                    byEntityId.put(c.entityId(), new SamlIdpProperties.RelyingParty(c.entityId(),
                            c.assertionConsumerServiceUrl(), c.defaultAuthnContextClassRef(),
                            c.singleLogoutServiceUrl(), c.signingCertificate(), c.optionsOrDefaults()));
                }
            }
        } catch (final RuntimeException e) {
            LOG.warn("SAML: could not load relying parties from the store, using static config only: {}",
                    e.getMessage());
        }
        return java.util.List.copyOf(byEntityId.values());
    }

    /**
     * The SAML attributes released to the SP. Always includes {@code mail} (back-compat). When the SP is
     * linked to an Application, it ALSO releases the same claim profile the app's OIDC tokens carry —
     * resolved via the shared {@link group.mfnr.authorization.service.UserInfoService} — so claims are
     * configured once on the application and apply to both protocols. Any failure degrades to {@code mail}.
     */
    private Map<String, String> attributes(final Authentication authentication, final String applicationId) {
        final Map<String, String> attributes = new HashMap<>();
        if (authentication.getPrincipal() instanceof UserCredentials user) {
            Optional.ofNullable(user.getEmail()).ifPresent(email -> attributes.put("mail", email));
        }
        if (applicationId != null && !applicationId.isBlank()) {
            try {
                final Map<String, String> profile = userInfoService.getOidcClaimProfile(authentication.getName());
                if (profile != null) {
                    profile.forEach((k, v) -> {
                        if (v != null && !v.isBlank()) {
                            attributes.put(k, v);
                        }
                    });
                }
            } catch (final RuntimeException e) {
                LOG.warn("SAML: could not resolve the application's claim profile for {} (releasing mail only): {}",
                        authentication.getName(), e.getMessage());
            }
        }
        return attributes;
    }

    /** The Application a SAML relying party is linked to, or {@code null} (standalone SP / store unreachable). */
    private String applicationIdForSp(final String spEntityId) {
        try {
            final String realm = RealmContextHolder.get() == null ? "master" : RealmContextHolder.get();
            return rpSource.load(realm).stream()
                    .filter(c -> c.entityId().equals(spEntityId))
                    .map(group.mfnr.authorization.amqp.saml.SamlRelyingPartyConfig::applicationId)
                    .filter(a -> a != null && !a.isBlank())
                    .findFirst()
                    .orElse(null);
        } catch (final RuntimeException e) {
            LOG.warn("SAML: could not resolve the application for SP {} ({}): {}", spEntityId, e.getClass().getSimpleName(), e.getMessage());
            return null;
        }
    }

    @GetMapping(value = "/saml/idp/metadata", produces = MediaType.APPLICATION_XML_VALUE)
    @ResponseBody
    public String metadata(final HttpServletRequest request) {
        requireSamlIdpEnabled();
        // MT-4: SSO endpoint is served under the realm path, so the published metadata must carry it.
        final String realm = RealmContextHolder.get() == null ? "master" : RealmContextHolder.get();
        final String ssoUrl = idpBaseUrl + "/realms/" + realm + "/saml/idp/sso";
        final String sloUrl = idpBaseUrl + "/realms/" + realm + "/saml/idp/slo";
        // Per-realm: publish THIS realm's signing certificate (derived from its active signing key), so an
        // SP that trusts this realm's metadata verifies assertions this realm actually signs.
        final String rawCert = credentialSource.forRealm(realm).signingCertificate();
        final String cert = rawCert == null ? "" : rawCert
                .replace("-----BEGIN CERTIFICATE-----", "").replace("-----END CERTIFICATE-----", "").replaceAll("\\s", "");
        return "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
                + "<md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" entityID=\""
                + properties.getEntityId() + "\">"
                + "<md:IDPSSODescriptor WantAuthnRequestsSigned=\"true\" protocolSupportEnumeration=\""
                + "urn:oasis:names:tc:SAML:2.0:protocol\">"
                + "<md:KeyDescriptor use=\"signing\"><ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">"
                + "<ds:X509Data><ds:X509Certificate>" + cert + "</ds:X509Certificate></ds:X509Data></ds:KeyInfo>"
                + "</md:KeyDescriptor>"
                + "<md:KeyDescriptor use=\"encryption\"><ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">"
                + "<ds:X509Data><ds:X509Certificate>" + cert + "</ds:X509Certificate></ds:X509Data></ds:KeyInfo>"
                + "</md:KeyDescriptor>"
                + "<md:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\""
                + sloUrl + "\"/>"
                + "<md:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\""
                + sloUrl + "\"/>"
                + "<md:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:SOAP\" Location=\""
                + sloUrl + "/soap\"/>"
                + "<md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</md:NameIDFormat>"
                + "<md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat>"
                + "<md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>"
                + "<md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</md:NameIDFormat>"
                + "<md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\""
                + ssoUrl + "\"/>"
                + "<md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\""
                + ssoUrl + "\"/>"
                + "</md:IDPSSODescriptor></md:EntityDescriptor>";
    }
}
