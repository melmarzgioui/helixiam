package io.helixiam.authorization.security.mfa.controller;

import io.helixiam.authorization.domain.UserCredentials;
import io.helixiam.authorization.security.flow.ResolveSavedRequestRedirect;
import io.helixiam.authorization.security.mfa.MfaAuthenticationCodeVerifier;
import io.helixiam.authorization.security.mfa.totp.QrCode;
import io.helixiam.authorization.service.MfaService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.util.Calendar;

@Controller
public class MfaAuthController {
    private static final String REDIRECT_PREFIX = "redirect:";
    private final QrCode qrCode;
    private final MfaAuthenticationCodeVerifier mfaAuthenticationCodeVerifier;
    private final MfaService mfaService;
    private final String spBaseUrl;
    private final io.helixiam.authorization.security.realm.SessionPolicyApplier sessionPolicyApplier;
    // SSO P1: after the second factor promotes the session, resume the originating /oauth2/authorize.
    private final ResolveSavedRequestRedirect savedRequestRedirect = new ResolveSavedRequestRedirect();
    private final io.helixiam.authorization.security.session.AuthTimeStamper authTimeStamper =
            new io.helixiam.authorization.security.session.AuthTimeStamper();

    @Autowired
    public MfaAuthController(final QrCode qrCode, final MfaAuthenticationCodeVerifier mfaAuthenticationCodeVerifier, final MfaService mfaService, @Value("${sp.base.url}") final String spBaseUrl,
                             final io.helixiam.authorization.security.realm.SessionPolicyApplier sessionPolicyApplier) {
        this.qrCode = qrCode;
        this.mfaAuthenticationCodeVerifier = mfaAuthenticationCodeVerifier;
        this.mfaService = mfaService;
        this.spBaseUrl = spBaseUrl;
        this.sessionPolicyApplier = sessionPolicyApplier;
    }

    private void applySessionPolicy(final HttpServletRequest request) {
        sessionPolicyApplier.applyOnLogin(request, io.helixiam.authorization.security.realm.RealmContextHolder.get());
    }

    @GetMapping(path = "/mfa/enable")
    public String requestEnableMfaFactor(@AuthenticationPrincipal final UserCredentials accountUserDetails, final Model model) {
        final String otpAuthUrl = "otpauth://totp/%s?secret=%s&digits=6".formatted("KubeDNA: " + accountUserDetails.getEmail(), accountUserDetails.getMfaSecret());
        model.addAttribute("qrCode", this.qrCode.dataUrl(otpAuthUrl));
        model.addAttribute("secret", accountUserDetails.getMfaSecret());
        model.addAttribute("skipEnable", false);

        try {
            final Calendar cal = Calendar.getInstance();
            cal.add(Calendar.DATE, -7);

            if (accountUserDetails.getCreationDate().after(cal.getTime())) {
                model.addAttribute("skipEnable", true);
            }
        } catch (final Exception e) {
            // swallow, skip not applied
        }


        return "mfa/enable";
    }


    @PostMapping(path = "/mfa/enable")
    public String processEnableMfaFactor(@RequestParam final String code, @AuthenticationPrincipal UserCredentials accountUserDetails, final Model model,
                                         final HttpServletRequest request, final HttpServletResponse response) {

        if("skip".equals(code)) {
            try {
                final Calendar cal = Calendar.getInstance();
                cal.add(Calendar.DATE, -7);

                if (accountUserDetails.getCreationDate().after(cal.getTime())) {
                    mfaService.unlockUser();
                    authTimeStamper.stamp(request); // SSO P2
                    applySessionPolicy(request); // SSO P3
                    return savedRequestRedirect.redirectView(request, response, spBaseUrl);
                }
            } catch (final Exception e) {
                // swallow, skip not applied
            }
        }

        if (accountUserDetails.isMfaEnabled()) {
            return REDIRECT_PREFIX + "/mfa/totp";
        }
        if (!mfaAuthenticationCodeVerifier.verify(accountUserDetails, code) || !mfaService.enableMfa(accountUserDetails)) {
            model.addAttribute("error", "true");
            return this.requestEnableMfaFactor(accountUserDetails, model);
        }

        return REDIRECT_PREFIX + spBaseUrl;
    }


    @GetMapping(path = "/mfa/totp")
    public String requestTotp() {
        return "mfa/totp";
    }

    @PostMapping(path = "/mfa/totp")
    public String processTotp(@RequestParam final String code, @AuthenticationPrincipal UserCredentials accountUserDetails, final Model model,
                              final HttpServletRequest request, final HttpServletResponse response) {
        if (!mfaAuthenticationCodeVerifier.verify(accountUserDetails, code)) {
            model.addAttribute("error", "true");
            return requestTotp();
        } else {
            mfaService.unlockUser();
            authTimeStamper.stamp(request); // SSO P2
            applySessionPolicy(request); // SSO P3
            return savedRequestRedirect.redirectView(request, response, spBaseUrl);
        }
    }
}