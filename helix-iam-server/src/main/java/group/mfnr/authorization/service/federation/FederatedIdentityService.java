package group.mfnr.authorization.service.federation;

import group.mfnr.authorization.domain.user.UserCredentials;
import group.mfnr.authorization.repository.UserCredentialsRepository;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Map;
import java.util.Optional;

/**
 * Helix IAM E5: the identity-domain operations the federation broker needs — resolve an existing
 * federated link, resolve a local user by email, record links, and just-in-time provision a new
 * federated user. JIT provisioning is deliberately CONSERVATIVE: the user is created usable but
 * passwordless, with NO roles and NO tenant membership — access is granted explicitly afterwards, so
 * a brokered login can never silently confer privileges.
 *
 * <p>Notes on this user model: {@code username} is the email ({@code @Email}); {@code accountLocked}
 * holds non-locked semantics ({@code isAccountNonLocked()} returns it), so {@code true} = usable.
 * Federated users are written directly (not via {@code UserService.save}, which is password +
 * signup-email oriented).
 */
@Service
public class FederatedIdentityService {

    private static final Logger LOG = LogManager.getLogger(FederatedIdentityService.class);

    private final UserCredentialsRepository users;
    private final FederatedLinkService links;

    public FederatedIdentityService(final UserCredentialsRepository users, final FederatedLinkService links) {
        this.users = users;
        this.links = links;
    }

    /** The local user previously linked to this external subject for the given provider, if any. */
    public Optional<String> findLinkedUser(final String idpAlias, final String externalSubject) {
        return links.findLinkedUser(idpAlias, externalSubject);
    }

    /** Record (or overwrite) the federated link. */
    public void link(final String idpAlias, final String externalSubject, final String userId) {
        links.link(idpAlias, externalSubject, userId);
    }

    /** A local user with this email (the username is the email), if any. */
    public Optional<String> findUserByEmail(final String email) {
        if (email == null || email.isBlank()) {
            return Optional.empty();
        }
        return users.findByUsername(email.toLowerCase()).map(UserCredentials::getUserId);
    }

    /**
     * Passwordless load of a user by id — backs federation session establishment after the external
     * IdP has authenticated the subject. Returns {@code null} when no such user exists.
     */
    public UserCredentials loadUser(final String userId) {
        return users.findByUserId(userId).orElse(null);
    }

    /**
     * Just-in-time provision a conservative federated user (usable, passwordless, no roles, no
     * tenant); returns its generated id.
     */
    @Transactional
    public String provisionUser(final String email, final Map<String, String> attributes) {
        // eID schemes (DigiD/eHerkenning/eIDAS) assert no email; fall back to the mapped subject-derived
        // username (BSN / PersonIdentifier / entityConcernedID) so the user always has a stable identifier.
        final String username = (email != null && !email.isBlank())
                ? email : (attributes != null ? attributes.get("username") : null);
        final UserCredentials user = new UserCredentials();
        user.setUsername(username);       // username == email, or the subject id for eID
        user.setPassword(null);           // federated: no local password
        user.setAccountLocked(true);      // true == non-locked == usable (per isAccountNonLocked)
        if (attributes != null) {
            user.getUserAttributes().putAll(attributes);
        }
        final String userId = users.save(user).getUserId();
        LOG.info("JIT-provisioned conservative federated user {} ({}) — no roles/tenant", userId, username);
        return userId;
    }
}
