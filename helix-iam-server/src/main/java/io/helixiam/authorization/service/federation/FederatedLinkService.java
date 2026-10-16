/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

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
        link(idpAlias, externalSubject, userId, null);
    }

    /** Record (or overwrite) the link with its provenance; an unknown one is stored as {@code AUTO}. */
    @Transactional
    public void link(final String idpAlias, final String externalSubject, final String userId,
                     final String createdVia) {
        final FederatedLinkEntity entity = new FederatedLinkEntity(idpAlias, externalSubject, userId);
        entity.setCreatedVia(io.helixiam.authorization.domain.federation.LinkProvenance.normalize(createdVia));
        repository.save(entity);
    }

    /** Round 6: how the link of (alias, subject) was created, if it exists. */
    @Transactional(readOnly = true)
    public Optional<String> provenance(final String idpAlias, final String externalSubject) {
        return repository.findById(FederatedLinkEntity.key(idpAlias, externalSubject))
                .map(l -> io.helixiam.authorization.domain.federation.LinkProvenance.normalize(l.getCreatedVia()));
    }

    /**
     * Task 21a: link (alias, subject) to {@code userId} only if it is free, race-safely, in one transaction: insert if
     * absent; if another owner holds it and {@code isLive} says that owner no longer counts (deleted, or not in the
     * caller's realm), delete that row only while it still names that owner, and insert again. Concurrent claims
     * serialise on the primary key, so exactly one row survives and every caller reads its owner back; a live link is
     * never overwritten.
     */
    @Transactional
    public LinkIfAbsent claim(final String idpAlias, final String externalSubject, final String userId,
                              final java.util.function.Predicate<String> isLive) {
        return claim(idpAlias, externalSubject, userId, isLive,
                io.helixiam.authorization.domain.federation.LinkProvenance.WALLET);
    }

    /** {@link #claim} recording {@code createdVia} on the row it inserts. */
    @Transactional
    public LinkIfAbsent claim(final String idpAlias, final String externalSubject, final String userId,
                              final java.util.function.Predicate<String> isLive, final String createdVia) {
        final String via = io.helixiam.authorization.domain.federation.LinkProvenance.normalize(createdVia);
        final String id = FederatedLinkEntity.key(idpAlias, externalSubject);
        boolean created = repository.insertIfAbsent(id, idpAlias, externalSubject, userId, via) == 1;
        String owner = owner(id);
        if (!owner.equals(userId) && !isLive.test(owner)) {
            repository.deleteIfOwnedBy(id, owner);
            created = repository.insertIfAbsent(id, idpAlias, externalSubject, userId, via) == 1;
            owner = owner(id);
        }
        return new LinkIfAbsent(owner, created && owner.equals(userId));
    }

    /** Round 6: set how {@code userId}'s links of {@code alias} count (confirm or revoke trust); how many changed. */
    @Transactional
    public int setProvenance(final String userId, final String idpAlias, final String createdVia) {
        return repository.updateProvenance(userId, idpAlias,
                io.helixiam.authorization.domain.federation.LinkProvenance.normalize(createdVia));
    }

    /** Round 6: every link of {@code userId} (alias, subject, provenance). */
    @Transactional(readOnly = true)
    public java.util.List<FederatedLinkEntity> linksOf(final String userId) {
        return repository.findAllByUserId(userId);
    }

    /** Round 6: the links created before the upgrade (the start-up report). */
    @Transactional(readOnly = true)
    public java.util.List<FederatedLinkEntity> legacyLinks() {
        return repository.findAllByCreatedVia(io.helixiam.authorization.domain.federation.LinkProvenance.LEGACY);
    }

    private String owner(final String id) {
        return repository.findUserIdById(id)
                .orElseThrow(() -> new IllegalStateException("The federated link could not be stored"));
    }

    /** The outcome of {@link #claim}: the subject's owner afterwards, and whether this call linked it. */
    public record LinkIfAbsent(String ownerUserId, boolean created) {
    }

    /**
     * Task 21a: remove every link {@code userId} has for {@code idpAlias} (a user can only ever unlink their own
     * links); returns how many were removed.
     */
    @Transactional
    public int unlinkAll(final String userId, final String idpAlias) {
        final java.util.List<FederatedLinkEntity> mine = repository.findAllByUserId(userId).stream()
                .filter(l -> idpAlias.equals(l.getIdpAlias())).toList();
        repository.deleteAll(mine);
        return mine.size();
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
