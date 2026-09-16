package group.mfnr.authorization.controller;

import com.j256.twofactorauth.TimeBasedOneTimePasswordUtil;
import group.mfnr.authorization.amqp.realm.RealmSettingsDto;
import group.mfnr.authorization.amqp.scope.ClaimDto;
import group.mfnr.authorization.amqp.scope.ClaimScopePublisher;
import group.mfnr.authorization.amqp.user.UserPublisher;
import group.mfnr.authorization.domain.UserRegister;
import group.mfnr.authorization.security.captcha.CaptchaService;
import group.mfnr.authorization.security.realm.RealmContextHolder;
import group.mfnr.authorization.security.realm.RealmSettingsResolver;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Controller
public class RegisterUserController {

  private static final Logger log = LoggerFactory.getLogger(RegisterUserController.class);

  private static final String VIEW_REGISTER_PAGE = "register/register";

  // Per-realm self-registration (SDD Task 6): claims that are never rendered as register-form inputs
  // (subject identifier, or collected/derived elsewhere), so the POST harvest+validation skips them.
  private static final java.util.Set<String> NON_FORM_CLAIMS = java.util.Set.of(
      "sub", "email", "email_verified", "phone_number_verified", "updated_at");

  private final UserPublisher userPublisher;
  private final Boolean registerEnabled;

  // Auth-hardening (feature 5): optional per-realm CAPTCHA gate. Field-injected so the constructor is
  // untouched; no-op when the realm has provider=none (the default).
  @Autowired(required = false)
  private CaptchaService captchaService;

  // Per-realm self-registration (SDD Task 5): field-injected so the constructor + its existing tests
  // stay intact.
  @Autowired(required = false)
  private RealmSettingsResolver realmSettingsResolver;

  @Autowired(required = false)
  private ClaimScopePublisher claimScopePublisher;

  @Autowired(required = false)
  private BrandingSupport brandingSupport;

  public RegisterUserController(final UserPublisher userPublisher, @Value("${user.register.enabled:true}") boolean registerEnabled) {
    this.userPublisher = userPublisher;
    this.registerEnabled = registerEnabled;
  }


  @GetMapping("/register")
  public String registration(final Model model) {
    final String realm = RealmContextHolder.get();
    model.addAttribute(ControllerConstants.USER_REGISTER, new UserRegister());
    model.addAttribute(ControllerConstants.ERRORS, new HashMap<>());
    model.addAttribute("registerEnabled", registrationEnabled(realm));
    model.addAttribute("registrationClaims", registrationClaims(realm));
    if (brandingSupport != null) {
      brandingSupport.apply(model);
    }
    addCaptchaModel(model);

    return VIEW_REGISTER_PAGE;
  }

  /** Effective per-realm enablement: the global master flag AND the realm's own switch. */
  private boolean registrationEnabled(final String realm) {
    if (!Boolean.TRUE.equals(registerEnabled)) {
      return false;                                   // global kill-switch wins
    }
    if (realmSettingsResolver == null) {
      return true;                                    // no resolver wired (e.g. minimal profile) → global only
    }
    final RealmSettingsDto s = realmSettingsResolver.get(realm);
    return s == null || s.registrationEnabled();
  }

  /** The realm's registration claim catalogue; empty (never null) if the lookup fails. */
  private List<ClaimDto> registrationClaims(final String realm) {
    if (claimScopePublisher == null) {
      return List.of();
    }
    try {
      final List<ClaimDto> claims = claimScopePublisher.claims(realm);
      return claims == null ? List.of() : claims;
    } catch (final RuntimeException e) {
      log.warn("Registration claim lookup failed for realm '{}'; rendering core fields only", realm, e);
      return List.of();                               // registration still works with core fields only
    }
  }

  /** Exposes the realm's CAPTCHA provider + site key so the template can render the widget when enabled. */
  private void addCaptchaModel(final Model model) {
    final String realm = RealmContextHolder.get();
    final boolean enabled = captchaService != null && captchaService.isEnabled(realm);
    model.addAttribute("captchaEnabled", enabled);
    model.addAttribute("captchaProvider", enabled ? captchaService.providerOf(realm) : "none");
    model.addAttribute("captchaSiteKey", enabled ? captchaService.siteKey(realm) : null);
  }


  @GetMapping("/register/verify/{code}")
  public void registrationSuccess(@PathVariable("code") final String code, final HttpServletRequest request,
                                  final HttpServletResponse httpServletResponse) throws IOException {
    userPublisher.verifyEmail(code);
    // MT-4: context-relative so it stays under the realm path (/realms/{realm}/login).
    httpServletResponse.sendRedirect(request.getContextPath() + "/login?info=verified");
  }

  @PostMapping(value = "/register")
  public String registration(@ModelAttribute(ControllerConstants.USER_REGISTER) final UserRegister userRegister, final Model model,
                             final HttpServletRequest request) {
    final Map<String, Boolean> errors = new HashMap<>();
    final String realm = RealmContextHolder.get();
    final boolean enabled = registrationEnabled(realm);
    final List<ClaimDto> claims = registrationClaims(realm);
    model.addAttribute("registerEnabled", enabled);
    model.addAttribute("registrationClaims", claims);
    if (brandingSupport != null) {
      brandingSupport.apply(model);
    }
    addCaptchaModel(model);

    // Registration closed for this realm → never sign up.
    if (!enabled) {
      model.addAttribute(ControllerConstants.USER_REGISTER, userRegister);
      model.addAttribute(ControllerConstants.ERRORS, errors);
      return VIEW_REGISTER_PAGE;
    }

    // Auth-hardening (feature 5): verify the CAPTCHA token server-side when the realm requires it.
    if (captchaService != null && captchaService.isEnabled(realm)
            && !captchaService.verify(realm, request.getParameter("cf-turnstile-response") != null
                ? request.getParameter("cf-turnstile-response") : request.getParameter("g-recaptcha-response"),
                clientIp(request))) {
      errors.put("invalid.captcha", true);
      model.addAttribute(ControllerConstants.USER_REGISTER, userRegister);
      model.addAttribute(ControllerConstants.ERRORS, errors);
      return VIEW_REGISTER_PAGE;
    }

    if (StringUtils.isEmpty(userRegister.getPassword()) || StringUtils.isEmpty(userRegister.getRepeatPassword()) || !userRegister.getPassword().equals(userRegister.getRepeatPassword())) {
      errors.put("invalid.password", true);
    }
    if (StringUtils.isEmpty(userRegister.getUsername())) {
      errors.put("invalid.username", true);
    }

    // Claim-driven fields: harvest every catalogue claim's request param, and require the mandatory ones.
    for (final ClaimDto claim : claims) {
      if (NON_FORM_CLAIMS.contains(claim.key())) {
        continue;
      }
      final String value = request.getParameter(claim.key());
      if (claim.mandatory() && StringUtils.isEmpty(value)) {
        errors.put("invalid.claim." + claim.key(), true);
      }
      if (!StringUtils.isEmpty(value)) {
        userRegister.putAttribute(claim.key(), value);
      }
    }

    if (!errors.isEmpty()) {
      model.addAttribute(ControllerConstants.USER_REGISTER, userRegister);
      model.addAttribute(ControllerConstants.ERRORS, errors);
      return VIEW_REGISTER_PAGE;
    }

    userRegister.setMfaSecret(TimeBasedOneTimePasswordUtil.generateBase32Secret());
    userRegister.setEmail(userRegister.getUsername());

    try {
      userPublisher.selfSignup(userRegister);
    } catch (final Exception e) {
      errors.put("invalid.username", true);
    }

    if (errors.isEmpty()) {
      return "register/success";
    }
    model.addAttribute(ControllerConstants.USER_REGISTER, userRegister);
    model.addAttribute(ControllerConstants.ERRORS, errors);
    return VIEW_REGISTER_PAGE;
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
}
