package io.helixiam.authorization.controller;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

/**
 * Story 4 (CLI auth): the human-facing verification page for the RFC 8628 device authorization grant.
 *
 * <p>The KubeDNA CLI shows the user a URL ({@code {issuer}/activate}) and a short user code. The user opens
 * the URL, signs in (this page is behind authentication like the rest of the login chain), and confirms the
 * code. The form posts the code to Spring Authorization Server's device verification endpoint
 * ({@code /oauth2/device_verification}); because the built-in {@code kubedna-cli} client requires no consent,
 * approval completes in one click and the CLI's token poll then succeeds. When the CLI opens the
 * {@code verification_uri_complete} (which carries {@code ?user_code=...}), the field is pre-filled.
 */
@Controller
public class DeviceActivationController {

    private final BrandingSupport brandingSupport;

    public DeviceActivationController(final BrandingSupport brandingSupport) {
        this.brandingSupport = brandingSupport;
    }

    @GetMapping("/activate")
    public String activate(@RequestParam(value = "user_code", required = false) final String userCode,
                           final Model model) {
        model.addAttribute("userCode", userCode == null ? "" : userCode);
        brandingSupport.apply(model);
        return "activate";
    }
}
