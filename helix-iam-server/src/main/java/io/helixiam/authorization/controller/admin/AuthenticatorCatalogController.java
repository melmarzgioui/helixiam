package io.helixiam.authorization.controller.admin;

import io.helixiam.authorization.flow.spi.Authenticator;
import io.helixiam.authorization.flow.spi.AuthenticatorMetadata;
import io.helixiam.authorization.flow.spi.AuthenticatorRegistry;
import io.helixiam.authorization.flow.spi.ConfigProperty;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * Helix IAM E8.5-S4: the catalogue of installed authenticators (from the in-process
 * {@link AuthenticatorRegistry}) that the Auth-flow editor lets an admin drop into a flow. Read-only;
 * realm is accepted for URL symmetry but the catalogue is platform-wide.
 */
@RestController
@RequestMapping("/admin/realms/{realmId}/authenticators")
public class AuthenticatorCatalogController {

    private final AuthenticatorRegistry registry;

    public AuthenticatorCatalogController(final AuthenticatorRegistry registry) {
        this.registry = registry;
    }

    @GetMapping
    public List<AuthenticatorCatalogEntry> list(@PathVariable final String realmId) {
        return registry.all().stream().map(AuthenticatorCatalogController::toEntry).toList();
    }

    private static AuthenticatorCatalogEntry toEntry(final Authenticator authenticator) {
        final AuthenticatorMetadata m = authenticator.metadata();
        return new AuthenticatorCatalogEntry(m.id(), m.displayName(), m.factorClass().name(), m.levelOfAssurance(),
                m.category().name(), m.configSchema());
    }

    /**
     * What the editor shows in its "add step" picker (with the per-step config schema it renders).
     * {@code category} is METHOD or CONDITION — the backend decides how the editor groups it, so the
     * console never guesses from {@code factorClass}/{@code levelOfAssurance}.
     */
    public record AuthenticatorCatalogEntry(String id, String displayName, String factorClass, int levelOfAssurance,
                                            String category, List<ConfigProperty> configSchema) {
    }
}
