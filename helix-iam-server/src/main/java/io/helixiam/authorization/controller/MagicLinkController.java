/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.controller;

import io.helixiam.authorization.domain.UserCredentials;
import io.helixiam.authorization.federation.FederatedSessionEstablisher;
import io.helixiam.authorization.security.audit.AuditContext;
import io.helixiam.authorization.security.audit.AuditEvent;
import io.helixiam.authorization.security.audit.AuditLog;
import io.helixiam.authorization.security.flow.ResolveSavedRequestRedirect;
import io.helixiam.authorization.security.mfa.MfaSessionState;
import io.helixiam.authorization.security.mfa.domain.MfaAuthentication;
import io.helixiam.authorization.security.realm.RealmContextHolder;
import io.helixiam.authorization.security.realm.SessionPolicyApplier;
import io.helixiam.authorization.security.session.AuthTimeStamper;
import io.helixiam.authorization.service.magiclink.MagicLinkService;
import io.helixiam.authorization.service.mfa.MfaPolicyService;
import io.helixiam.authorization.service.mfa.TotpService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.server.ResponseStatusException;

import java.util.Map;

/**
 * 1.0 item 6: passwordless sign-in by emailed link (realm-relative, only when the realm enabled it — else 404).
 *
 * <ol>
 *   <li>{@code GET/POST /login/magic}: ask for an email address; the answer is the same whether or not an account
 *       exists.</li>
 *   <li>{@code GET /login/magic/verify?token=…}: a confirmation page only — mail scanners that prefetch links do not
 *       use the link up.</li>
 *   <li>{@code POST /login/magic/verify}: consumes the link once and signs the user in. The link is a first factor:
 *       when the realm requires TOTP (or the user enrolled), the session is held behind the second factor exactly
 *       like after a password.</li>
 * </ol>
 */
@Controller
public class MagicLinkController {

    private static final org.apache.logging.log4j.Logger LOG = org.apache.logging.log4j.LogManager.getLogger(MagicLinkController.class);

    private final MagicLinkService magicLinks;
    private final FederatedSessionEstablisher sessions;
    private final MfaPolicyService mfaPolicy;
    private final TotpService totp;
    private final SessionPolicyApplier sessionPolicy;
    private final AuditLog auditLog;
    private final BrandingSupport branding;
    private final String spBaseUrl;
    private final String idpBaseUrl;
    private final ResolveSavedRequestRedirect savedRequestRedirect = new ResolveSavedRequestRedirect();
    private final AuthTimeStamper authTimeStamper = new AuthTimeStamper();

    public MagicLinkController(final MagicLinkService magicLinks, final FederatedSessionEstablisher sessions,
                               final MfaPolicyService mfaPolicy, final TotpService totp,
                               final SessionPolicyApplier sessionPolicy, final AuditLog auditLog,
                               final BrandingSupport branding, @Value("${sp.base.url}") final String spBaseUrl,
                               @Value("${idp.base.url:}") final String idpBaseUrl) {
        this.magicLinks = magicLinks;
        this.sessions = sessions;
        this.mfaPolicy = mfaPolicy;
        this.totp = totp;
        this.sessionPolicy = sessionPolicy;
        this.auditLog = auditLog;
        this.branding = branding;
        this.spBaseUrl = spBaseUrl;
        this.idpBaseUrl = idpBaseUrl == null ? "" : idpBaseUrl.trim().replaceAll("/+$", "");
    }

    @GetMapping("/login/magic")
    public String requestPage(final Model model) {
        requireEnabled();
        branding.apply(model);
        return "magic/request";
    }

    @PostMapping("/login/magic")
    public String request(@RequestParam(required = false) final String email, final HttpServletRequest request,
                          final Model model) {
        requireEnabled();
        final String realm = RealmContextHolder.get();
        // Security: the link's host comes from configuration (idp.base.url), never from the request — a forged
        // Host / X-Forwarded-Host would otherwise send the victim a valid token on the attacker's domain.
        if (idpBaseUrl.isEmpty()) {
            LOG.error("Magic link not sent: idp.base.url (IDP_BASE_URL) is not configured");
        } else {
            magicLinks.request(realm, email, AuditContext.clientIp(request), idpBaseUrl + "/realms/" + realm);
        }
        branding.apply(model);
        return "magic/sent";
    }

    @GetMapping("/login/magic/verify")
    public String confirmPage(@RequestParam(required = false) final String token, final Model model) {
        requireEnabled();
        model.addAttribute("token", token);
        branding.apply(model);
        return "magic/confirm";
    }

    @PostMapping("/login/magic/verify")
    public String verify(@RequestParam(required = false) final String token, final HttpServletRequest request,
                         final HttpServletResponse response, final Model model) {
        requireEnabled();
        final String realm = RealmContextHolder.get();
        final String userId = magicLinks.consume(realm, token).orElse(null);
        if (userId == null) {
            response.setStatus(HttpStatus.BAD_REQUEST.value());
            branding.apply(model);
            return "magic/invalid";
        }
        final UserCredentials user = sessions.loadUser(userId);
        final Authentication auth = UsernamePasswordAuthenticationToken.authenticated(user, null, user.getAuthorities());
        request.getSession(true);
        request.changeSessionId(); // new sign-in, new session id
        MfaSessionState.clear(request);
        auditLog.emit(AuditEvent.authn(io.helixiam.authorization.security.audit.AuditContext.nowIso(), "LOGIN_SUCCESS",
                realm, user.getEmail(), AuditContext.clientIp(request), "SUCCESS", Map.of("method", "magic_link")));

        final boolean enrolled = totp.isEnrolled(userId);
        if (enrolled || mfaPolicy.required(realm)) {
            sessions.persist(new MfaAuthentication(auth), request, response);
            return "redirect:" + (enrolled ? "/mfa/totp" : "/mfa/enable");
        }
        sessions.persist(auth, request, response);
        authTimeStamper.stamp(request);
        sessionPolicy.applyOnLogin(request, realm);
        return savedRequestRedirect.redirectView(request, response, spBaseUrl);
    }

    private void requireEnabled() {
        if (!magicLinks.enabled(RealmContextHolder.get())) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND);
        }
    }
}
