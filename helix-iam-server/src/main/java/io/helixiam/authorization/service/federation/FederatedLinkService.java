package io.helixiam.authorization.service.federation;

import io.helixiam.authorization.domain.federation.FederatedLinkEntity;
import io.helixiam.authorization.repository.federation.FederatedLinkRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

/**
 * Helix IAM E5: the account-linking persistence behind the federation broker. Resolves the local
 * user previously linked to an (idp alias, external subject) pair and records new links. JIT user
 * provisioning + email-based lookup involve the user domain and are wired with the federation
 * controller/AMQP endpoint separately.
 */
@Service
public class FederatedLinkService {

    private final FederatedLinkRepository repository;

    public FederatedLinkService(final FederatedLinkRepository repository) {
        this.repository = repository;
    }

    /** The local user linked to this external subject for the given provider, if any. */
    public Optional<String> findLinkedUser(final String idpAlias, final String externalSubject) {
        return repository.findById(FederatedLinkEntity.key(idpAlias, externalSubject))
                .map(FederatedLinkEntity::getUserId);
    }

    /** Record (or overwrite) the link from an external subject to a local user. */
    @Transactional
    public void link(final String idpAlias, final String externalSubject, final String userId) {
        repository.save(new FederatedLinkEntity(idpAlias, externalSubject, userId));
    }

    /** B9: every federated identity a user has connected — for the account console's "Connected accounts". */
    @Transactional(readOnly = true)
    public java.util.List<io.helixiam.authorization.domain.federation.FederatedLinkView> linksForUser(final String userId) {
        return repository.findAllByUserId(userId).stream()
                .map(io.helixiam.authorization.domain.federation.FederatedLinkView::from).toList();
    }

    /**
     * B9: disconnect a provider the user previously linked. Scoped to the caller's own links (a user can
     * only ever unlink their own account); {@code false} when they have no link for that provider.
     */
    @Transactional
    public boolean unlink(final String userId, final String idpAlias) {
        return repository.findAllByUserId(userId).stream()
                .filter(l -> idpAlias.equals(l.getIdpAlias()))
                .findFirst()
                .map(l -> {
                    repository.delete(l);
                    return true;
                }).orElse(false);
    }
}
