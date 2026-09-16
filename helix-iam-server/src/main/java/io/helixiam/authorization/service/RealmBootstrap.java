package io.helixiam.authorization.service;

import io.helixiam.authorization.domain.realm.RealmConfig;
import io.helixiam.authorization.service.client.CliClientBootstrapService;
import io.helixiam.authorization.service.client.ConsoleClientBootstrapService;
import io.helixiam.authorization.service.flow.AuthFlowService;
import io.helixiam.authorization.service.realm.RealmAdminBootstrapService;
import io.helixiam.authorization.service.role.DefaultRolesBootstrapService;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;

/**
 * Helix IAM E1.3/E2.5: seeds the bootstrap administration realm ("master") on startup so a
 * fresh deployment always has the realm that administers all others, plus its built-in
 * browser login flow (E2.5) and an {@code admin} role + admin user (master = admin/admin,
 * env-overridable). Every other realm with a config is bootstrapped the same way. Idempotent.
 */
@Component
public class RealmBootstrap implements ApplicationRunner {

    private static final Logger LOG = LogManager.getLogger(RealmBootstrap.class);

    private final RealmService realmService;
    private final AuthFlowService authFlowService;
    private final RealmAdminBootstrapService realmAdminBootstrapService;
    private final CliClientBootstrapService cliClientBootstrapService;
    private final ConsoleClientBootstrapService consoleClientBootstrapService;
    private final DefaultRolesBootstrapService defaultRolesBootstrapService;

    public RealmBootstrap(final RealmService realmService, final AuthFlowService authFlowService,
                          final RealmAdminBootstrapService realmAdminBootstrapService,
                          final CliClientBootstrapService cliClientBootstrapService,
                          final ConsoleClientBootstrapService consoleClientBootstrapService,
                          final DefaultRolesBootstrapService defaultRolesBootstrapService) {
        this.realmService = realmService;
        this.authFlowService = authFlowService;
        this.realmAdminBootstrapService = realmAdminBootstrapService;
        this.cliClientBootstrapService = cliClientBootstrapService;
        this.consoleClientBootstrapService = consoleClientBootstrapService;
        this.defaultRolesBootstrapService = defaultRolesBootstrapService;
    }

    @Override
    public void run(final ApplicationArguments args) {
        try {
            realmService.ensureAdminRealm();
            authFlowService.ensureBrowserFlow(RealmConfig.ADMIN_REALM_ID);
            // ensureRealmAdmin creates the tenant row + admin role + admin user FIRST — the tenant must exist
            // before default roles can be inserted (user_roles.tenant_id FKs to tenant). ensureDefaultRoles then
            // adds the system/default flags, the user/auditor roles, and the admin→realm-admin grant idempotently.
            realmAdminBootstrapService.ensureRealmAdmin(RealmConfig.ADMIN_REALM_ID);
            defaultRolesBootstrapService.ensureDefaultRoles(RealmConfig.ADMIN_REALM_ID);
            cliClientBootstrapService.ensureCliClient(RealmConfig.ADMIN_REALM_ID);
            // Self-heal + reconcile the built-in console client every startup (recreated if deleted, redirect
            // URIs refreshed from HELIX_CONSOLE_BASE_URL) so the admin console can always log in via SSO.
            consoleClientBootstrapService.ensureConsoleClient(RealmConfig.ADMIN_REALM_ID);
            // Every realm that has a config also gets the default roles + an admin user + the built-in CLI + console clients.
            realmService.list().forEach(realm -> {
                try {
                    realmAdminBootstrapService.ensureRealmAdmin(realm.getRealmId());
                    defaultRolesBootstrapService.ensureDefaultRoles(realm.getRealmId());
                    cliClientBootstrapService.ensureCliClient(realm.getRealmId());
                    consoleClientBootstrapService.ensureConsoleClient(realm.getRealmId());
                } catch (final RuntimeException e) {
                    LOG.warn("Could not bootstrap admin/CLI/console client for realm {}: {}", realm.getRealmId(), e.getMessage());
                }
            });
        } catch (final RuntimeException e) {
            // Non-fatal: a startup race or read-only replica shouldn't crash the service;
            // the admin realm is also created lazily via getOrDefault fallbacks.
            LOG.warn("Could not seed the admin realm/flow at startup: {}", e.getMessage());
        }
    }
}
