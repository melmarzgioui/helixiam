/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.service.federation;

import io.helixiam.authorization.domain.federation.LinkProvenance;
import io.helixiam.authorization.security.audit.AuditContext;
import io.helixiam.authorization.security.audit.AuditEvent;
import io.helixiam.authorization.security.audit.AuditLog;
import io.helixiam.authorization.service.adminrbac.PrivilegedLegacyLinkReport;
import io.helixiam.common.log.LogSafe;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import java.util.List;
import java.util.Map;

/**
 * Round 6: V86 cannot see the identity providers of the realm config folder (they are loaded at start-up), so a
 * pre-upgrade link whose alias it could not place in exactly one realm is stored {@code UNRESOLVED} (never trusted).
 * When the application is ready (after every start-up runner, the config-folder loader included), each such row is
 * resolved once:
 * <ul>
 *   <li>the alias now belongs to exactly one stored realm (database and realm config folder): the link moves there and
 *       becomes {@code LEGACY} ({@code WALLET} for a wallet provider), audited as {@code LEGACY_LINK_RESOLVED};</li>
 *   <li>when no stored provider uses the alias, the login's provider registry decides: if exactly one provider
 *       definition (a static {@code helix.federation.*} one) has the alias and it serves the link's candidate realm,
 *       the link stays there and becomes {@code LEGACY} the same way;</li>
 *   <li>otherwise it becomes {@code AUTO} (it signs no administrator in) and the start-up report lists it as
 *       {@code AMBIGUOUS} until a realm admin confirms it.</li>
 * </ul>
 * Links made at run time are never touched (they are never {@code UNRESOLVED}). Safe with several replicas: every
 * update is conditional on the row still being {@code UNRESOLVED}, so exactly one replica applies (and audits) it.
 * Then the start-up report runs.
 */
@Component
public class UnresolvedLinkReconciler {

    private static final Logger LOG = LogManager.getLogger(UnresolvedLinkReconciler.class);

    /** What happened to one row. */
    public record Resolution(String id, String idpAlias, String realm, String createdVia) {
    }

    private final JdbcTemplate jdbc;
    private final TransactionTemplate tx;
    private final AuditLog audit;
    private final PrivilegedLegacyLinkReport report;

    public UnresolvedLinkReconciler(final JdbcTemplate jdbc, final PlatformTransactionManager transactions,
                                    final AuditLog audit, final PrivilegedLegacyLinkReport report) {
        this.jdbc = jdbc;
        this.tx = new TransactionTemplate(transactions);
        this.audit = audit;
        this.report = report;
    }

    /** The registry the login uses: stored, realm-config-folder and static ({@code helix.federation.*}) providers. */
    private io.helixiam.authorization.federation.IdentityProviderRegistry registry;

    @org.springframework.beans.factory.annotation.Autowired(required = false)
    public void setRegistry(final io.helixiam.authorization.federation.IdentityProviderRegistry registry) {
        this.registry = registry;
    }

    @EventListener(ApplicationReadyEvent.class)
    public void onReady() {
        try {
            reconcile();
        } catch (final RuntimeException e) {
            LOG.warn("Could not resolve pre-upgrade federated links: {}", e.getClass().getSimpleName());
        }
        report.runSafely();
    }

    /** Resolves every {@code UNRESOLVED} link; returns what this call changed. */
    public List<Resolution> reconcile() {
        final List<Map<String, Object>> rows = jdbc.queryForList(
                "SELECT id, realm_id, idp_alias, external_subject, user_id FROM federated_link WHERE created_via = ?",
                LinkProvenance.UNRESOLVED);
        final List<Resolution> done = new java.util.ArrayList<>();
        for (final Map<String, Object> row : rows) {
            final Resolution r;
            try {
                r = tx.execute(t -> resolve((String) row.get("id"), (String) row.get("realm_id"),
                        (String) row.get("idp_alias"), (String) row.get("external_subject"), (String) row.get("user_id")));
            } catch (final RuntimeException e) {
                // E.g. a unique violation because another replica resolved this row (or its target) first: skip it,
                // the other replica's result stands, and the remaining rows still get resolved.
                LOG.debug("Skipped resolving a pre-upgrade link of provider {}: {}",
                        LogSafe.sanitize(String.valueOf(row.get("idp_alias"))), e.getClass().getSimpleName());
                continue;
            }
            if (r != null) {
                done.add(r);
            }
        }
        return done;
    }

    /** The realm a link resolves to and its provenance there, or null when it stays ambiguous. */
    private record Target(String realm, String via) {
    }

    /**
     * Where a link resolves, or null (AUTO, reported AMBIGUOUS). Stored providers (database and realm config folder)
     * decide when any uses the alias: exactly one realm, and no static provider of that alias, resolves there. Only when
     * no stored provider uses the alias does the login's registry decide: it must serve the alias in the link's
     * candidate realm, and every realm must be served by one and the same provider definition (one issuer).
     */
    private Target target(final String candidate, final String alias) {
        final List<Map<String, Object>> owners = jdbc.queryForList(
                "SELECT DISTINCT realm_id, lower(protocol) AS protocol FROM identity_provider WHERE alias = ?", alias);
        final boolean isStatic = registry != null && registry.isStatic(alias);
        if (!owners.isEmpty()) {
            final long realms = owners.stream().map(o -> o.get("realm_id")).distinct().count();
            if (realms != 1 || isStatic) {
                return null; // stored in several realms, or colliding with a static provider of the same alias
            }
            final String protocol = String.valueOf(owners.get(0).get("protocol"));
            return new Target((String) owners.get(0).get("realm_id"),
                    List.of("eudi-wallet", "openid4vp", "wallet").contains(protocol) ? LinkProvenance.WALLET
                            : LinkProvenance.LEGACY);
        }
        if (registry == null || candidate == null) {
            return null;
        }
        final List<io.helixiam.authorization.federation.spi.IdentityProvider> definitions =
                registry.named(alias).stream().distinct().toList();
        if (definitions.size() != 1) {
            return null; // different definitions of the alias in different realms
        }
        try {
            if (registry.get(candidate, alias) != definitions.get(0)) {
                return null;
            }
        } catch (final IllegalArgumentException notServed) {
            return null;
        }
        return new Target(candidate, definitions.get(0).metadata().protocol()
                == io.helixiam.authorization.federation.spi.IdpMetadata.Protocol.WALLET
                ? LinkProvenance.WALLET : LinkProvenance.LEGACY);
    }

    private Resolution resolve(final String id, final String candidate, final String alias, final String subject,
                               final String userId) {
        final Target target = target(candidate, alias);
        if (target != null) {
            final String realm = target.realm();
            final String via = target.via();
            final String newId = io.helixiam.authorization.domain.federation.FederatedLinkEntity.key(realm, alias, subject);
            final boolean taken = !newId.equals(id) && Boolean.TRUE.equals(jdbc.queryForObject(
                    "SELECT EXISTS (SELECT 1 FROM federated_link WHERE id = ?)", Boolean.class, newId));
            if (!taken) {
                final int changed = jdbc.update("UPDATE federated_link SET id = ?, realm_id = ?, created_via = ?, "
                        + "realm_ambiguous = false WHERE id = ? AND created_via = ?", newId, realm, via, id,
                        LinkProvenance.UNRESOLVED);
                if (changed == 1) {
                    LOG.info("Resolved pre-upgrade link of provider {} to realm {} ({})", LogSafe.sanitize(alias),
                            LogSafe.sanitize(realm), via);
                    audit.emit(AuditEvent.admin(AuditContext.nowIso(), "LEGACY_LINK_RESOLVED", realm, "system", null,
                            "user", userId, "SUCCESS", Map.of("idpAlias", alias, "createdVia", via)));
                    return new Resolution(newId, alias, realm, via);
                }
                return null; // another replica got there first
            }
        }
        final int changed = jdbc.update("UPDATE federated_link SET created_via = ? WHERE id = ? AND created_via = ?",
                LinkProvenance.AUTO, id, LinkProvenance.UNRESOLVED);
        if (changed == 1) {
            LOG.warn("A pre-upgrade link of provider {} could not be placed in one realm; it signs no administrator in "
                    + "until a realm admin confirms it.", LogSafe.sanitize(alias));
            return new Resolution(id, alias, null, LinkProvenance.AUTO);
        }
        return null;
    }
}
