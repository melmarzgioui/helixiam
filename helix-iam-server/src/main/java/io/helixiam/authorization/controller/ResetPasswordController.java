package io.helixiam.authorization.controller;

import io.helixiam.authorization.amqp.user.UserPublisher;
import io.helixiam.authorization.domain.ChangePassword;
import io.helixiam.authorization.security.captcha.CaptchaService;
import io.helixiam.authorization.security.realm.RealmContextHolder;
import io.helixiam.common.exception.ValidationException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

@Controller
public class ResetPasswordController {

    private final UserPublisher userPublisher;



    private final String spBaseUrl;

    // Auth-hardening (feature 5): optional per-realm CAPTCHA gate (field-injected; no-op when provider=none).
    @Autowired(required = false)
    private CaptchaService captchaService;

    public ResetPasswordController(@Value("${sp.base.url}") final String spBaseUrl, final UserPublisher userPublisher) {
        this.spBaseUrl = spBaseUrl;
        this.userPublisher = userPublisher;
    }


    @GetMapping("/reset/password")
    public String passwordReset(final Model model) {
        addCaptchaModel(model);
        return "reset/password";
    }

    /** Exposes the realm's CAPTCHA provider + site key so the template can render the widget when enabled. */
    private void addCaptchaModel(final Model model) {
        final String realm = RealmContextHolder.get();
        final boolean enabled = captchaService != null && captchaService.isEnabled(realm);
        model.addAttribute("captchaEnabled", enabled);
        model.addAttribute("captchaProvider", enabled ? captchaService.providerOf(realm) : "none");
        model.addAttribute("captchaSiteKey", enabled ? captchaService.siteKey(realm) : null);
    }

    /** Client IP honouring {@code X-Forwarded-For}, for the CAPTCHA {@code remoteip} parameter. */
    private static String clientIp(final HttpServletRequest request) {
        final String forwarded = request.getHeader("X-Forwarded-For");
        if (forwarded != null && !forwarded.isBlank()) {
            final int comma = forwarded.indexOf(',');
            return (comma > 0 ? forwarded.substring(0, comma) : forwarded).trim();
        }
        return request.getRemoteAddr();
    }

    @GetMapping("/reset/password/{code}")
    public String passwordReset(@PathVariable("code") final String code, final Model model) {
        model.addAttribute(ControllerConstants.CHANGE_PASSSWORD, new ChangePassword(code));
        model.addAttribute(ControllerConstants.ERRORS, new HashMap<>());

        return "reset/set";
    }

    @PostMapping(path = "/reset/password/set", produces = MediaType.APPLICATION_JSON_VALUE)
    public String resetPasswordRequest(@ModelAttribute(ControllerConstants.CHANGE_PASSSWORD) final ChangePassword changePassword, final Model model, final HttpServletResponse response) {
        final Map<String, Boolean> errors = new HashMap<>();
        if (StringUtils.isEmpty(changePassword.getNewPassword()) || StringUtils.isEmpty(changePassword.getRepeatPassword()) || !changePassword.getNewPassword().equals(changePassword.getRepeatPassword())) {
            errors.put("invalid.password", true);
        } else {
            try {
                if (Boolean.TRUE.equals(userPublisher.resetPasswordUpdate(changePassword))) {

                    response.sendRedirect(spBaseUrl);
                    return null;
                }
            } catch (final IOException | ValidationException responseException) {
                // swallow
            }
        }

        model.addAttribute(ControllerConstants.CHANGE_PASSSWORD, changePassword);
        model.addAttribute(ControllerConstants.ERRORS, errors);
        return "reset/set";
    }


    @PostMapping(path = "/reset/password", produces = MediaType.APPLICATION_JSON_VALUE)
    public String resetPasswordRequest(@ModelAttribute("username") final String username, final Model model,
                                       final HttpServletRequest request) {
        addCaptchaModel(model);
        // Auth-hardening (feature 5): verify the CAPTCHA token server-side when the realm requires it.
        final String realm = RealmContextHolder.get();
        if (captchaService != null && captchaService.isEnabled(realm)
                && !captchaService.verify(realm, request.getParameter("cf-turnstile-response") != null
                    ? request.getParameter("cf-turnstile-response") : request.getParameter("g-recaptcha-response"),
                    clientIp(request))) {
            model.addAttribute(ControllerConstants.ERRORS, "captcha");
            return "reset/password";
        }
        if (StringUtils.isEmpty(username)) {
            model.addAttribute(ControllerConstants.ERRORS, "username");

            return "reset/password";
        }

        userPublisher.resetPasswordRequest(username);

        return "reset/success";
    }
}
