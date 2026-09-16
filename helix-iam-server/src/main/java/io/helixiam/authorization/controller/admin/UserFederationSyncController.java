package io.helixiam.authorization.controller.admin;

import io.helixiam.authorization.federation.ldap.LdapSyncService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Helix IAM B10: admin trigger for an on-demand LDAP/AD user sync — the backend behind the console's
 * "Sync users" button on the User federation screen. Enumerates the named directory and provisions/links
 * each user as a passwordless federated account (the same path an LDAP login uses).
 */
@RestController
@RequestMapping("/admin/realms/{realmId}/user-federation/{alias}")
@Tag(name = "User federation", description = "On-demand LDAP/AD user sync.")
public class UserFederationSyncController {

    private final LdapSyncService syncService;

    public UserFederationSyncController(final LdapSyncService syncService) {
        this.syncService = syncService;
    }

    @PostMapping("/sync")
    @Operation(summary = "Sync LDAP users", description = "Import/refresh users from the named LDAP/AD provider.")
    public ResponseEntity<LdapSyncService.Result> sync(@PathVariable final String realmId, @PathVariable final String alias) {
        return ResponseEntity.ok(syncService.sync(realmId, alias));
    }
}
