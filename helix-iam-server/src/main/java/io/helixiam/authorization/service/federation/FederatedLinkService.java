/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.service.federation;

import io.helixiam.authorization.domain.federation.FederatedLinkEntity;
import io.helixiam.authorization.domain.federation.LinkProvenance;
import io.helixiam.authorization.repository.federation.FederatedLinkRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;
import java.util.function.Predicate;

/**
 * Helix IAM E5: the account-linking persistence behind the federation broker. Resolves the local user previously
 * linked to an (idp alias, external subject) pair and records new links.
 *
 * <p>Round 6: links are <b>realm-scoped</b>. Every lookup, insert, update and delete names the realm; a link of realm A
 * never signs anyone in to realm B, and the key is {@code (realm_id, idp_alias, external_subject)}.
 */
@Service
public class FederatedLinkService {

    private final FederatedLinkRepository repository;

    public FederatedLinkService(final FederatedLinkRepository repository) {
        this.repository = repository;
    }

    /** The local user linked to this external subject for the realm's provider, if any. */
    public Optional<String> findLinkedUser(final String realmId, final String idpAlias, final String externalSubject) {
        return find(realmId, idpAlias, externalSubject).map(FederatedLinkEntity::getUserId);
    }

    /** Record (or overwrite) the link in {@code realmId}; an unknown provenance is stored as {@code AUTO}. */
    @Transactional
    public void link(final String realmId, final String idpAlias, final String externalSubject, final String userId,
                     final String createdVia) {
        requireRealm(realmId);
        final FederatedLinkEntity entity = new FederatedLinkEntity(realmId, idpAlias, externalSubject, userId);
        entity.setCreatedVia(LinkProvenance.normalize(createdVia));
        repository.save(entity);
    }

    /** How the link of (realm, alias, subject) was made, if it exists. */
    @Transactional(readOnly = true)
    public Optional<String> provenance(final String realmId, final String idpAlias, final String externalSubject) {
        return find(realmId, idpAlias, externalSubject).map(l -> LinkProvenance.normalize(l.getCreatedVia()));
    }

    /**
     * Task 21a: link (realm, alias, subject) to {@code userId} only if it is free, race-safely, in one transaction:
     * insert if absent; if another owner holds it and {@code isLive} says that owner no longer counts (the user no
     * longer exists), delete that row only while it still names that owner, and insert again. A live link is never
     * overwritten.
     */
    @Transactional
    public LinkIfAbsent claim(final String realmId, final String idpAlias, final String externalSubject,
                              final String userId, final Predicate<String> isLive, final String createdVia) {
        requireRealm(realmId);
        final String via = LinkProvenance.normalize(createdVia);
        final String id = FederatedLinkEntity.key(realmId, idpAlias, externalSubject);
        boolean created = repository.insertIfAbsent(id, realmId, idpAlias, externalSubject, userId, via) == 1;
        String owner = owner(id);
        if (!owner.equals(userId) && !isLive.test(owner)) {
            repository.deleteIfOwnedBy(id, owner);
            created = repository.insertIfAbsent(id, realmId, idpAlias, externalSubject, userId, via) == 1;
            owner = owner(id);
        }
        return new LinkIfAbsent(owner, created && owner.equals(userId));
    }

    private String owner(final String id) {
        return repository.findUserIdById(id)
                .orElseThrow(() -> new IllegalStateException("The federated link could not be stored"));
    }

    /** The outcome of {@link #claim}: the subject's owner afterwards, and whether this call linked it. */
    public record LinkIfAbsent(String ownerUserId, boolean created) {
    }

    /** Remove every link {@code userId} has for the realm's {@code idpAlias}; returns how many were removed. */
    @Transactional
    public int unlinkAll(final String realmId, final String userId, final String idpAlias) {
        final List<FederatedLinkEntity> mine = linksOf(realmId, userId).stream()
                .filter(l -> idpAlias.equals(l.getIdpAlias())).toList();
        repository.deleteAll(mine);
        return mine.size();
    }

    /** B9: the user's federated identities in {@code realmId}, for the account console's "Connected accounts". */
    @Transactional(readOnly = true)
    public List<io.helixiam.authorization.domain.federation.FederatedLinkView> linksForUser(final String realmId,
                                                                                         final String userId) {
        return linksOf(realmId, userId).stream()
                .map(io.helixiam.authorization.domain.federation.FederatedLinkView::from).toList();
    }

    /** B9: disconnect a provider the user linked in {@code realmId}; {@code false} when there is no such link. */
    @Transactional
    public boolean unlink(final String realmId, final String userId, final String idpAlias) {
        return linksOf(realmId, userId).stream()
                .filter(l -> idpAlias.equals(l.getIdpAlias()))
                .findFirst()
                .map(l -> {
                    repository.delete(l);
                    return true;
                }).orElse(false);
    }

    /** Round 6: set how the user's links of the realm's {@code alias} count (confirm or revoke trust). */
    @Transactional
    public int setProvenance(final String realmId, final String userId, final String idpAlias,
                             final String createdVia) {
        requireRealm(realmId);
        return repository.updateProvenance(realmId, userId, idpAlias, LinkProvenance.normalize(createdVia));
    }

    /** Round 6: every link of {@code userId} in {@code realmId}. */
    @Transactional(readOnly = true)
    public List<FederatedLinkEntity> linksOf(final String realmId, final String userId) {
        return realmId == null || userId == null ? List.of() : repository.findAllByRealmIdAndUserId(realmId, userId);
    }

    /** Round 6: every link of the realm's {@code alias}. */
    @Transactional(readOnly = true)
    public List<FederatedLinkEntity> linksOfProvider(final String realmId, final String alias) {
        return realmId == null || alias == null ? List.of() : repository.findAllByRealmIdAndIdpAlias(realmId, alias);
    }

    /** Round 6: the links created before the upgrade (the start-up report). */
    @Transactional(readOnly = true)
    public List<FederatedLinkEntity> legacyLinks() {
        return repository.findAllByCreatedVia(LinkProvenance.LEGACY);
    }

    /** Round 6: links the upgrade placed in a realm by a fallback and nobody confirmed yet (AUTO). */
    @Transactional(readOnly = true)
    public List<FederatedLinkEntity> ambiguousLinks() {
        return repository.findAllByRealmAmbiguousTrueAndCreatedVia(LinkProvenance.AUTO);
    }

    /** Round 6: links the upgrade could not place in a realm; they never sign anyone in. */
    @Transactional(readOnly = true)
    public List<FederatedLinkEntity> linksWithoutRealm() {
        return repository.findAllByRealmIdIsNull();
    }

    private Optional<FederatedLinkEntity> find(final String realmId, final String idpAlias, final String subject) {
        if (realmId == null || idpAlias == null || subject == null) {
            return Optional.empty();
        }
        return repository.findById(FederatedLinkEntity.key(realmId, idpAlias, subject))
                .filter(l -> realmId.equals(l.getRealmId()));
    }

    private static void requireRealm(final String realmId) {
        if (realmId == null || realmId.isBlank()) {
            throw new IllegalArgumentException("A federated link belongs to a realm");
        }
    }
}
