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
 *   <li>the alias now belongs to exactly one realm: the link moves there and becomes {@code LEGACY} ({@code WALLET} for a
 *       wallet provider), audited as {@code LEGACY_LINK_RESOLVED};</li>
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
                "SELECT id, idp_alias, external_subject, user_id FROM federated_link WHERE created_via = ?",
                LinkProvenance.UNRESOLVED);
        final List<Resolution> done = new java.util.ArrayList<>();
        for (final Map<String, Object> row : rows) {
            final Resolution r = tx.execute(t -> resolve((String) row.get("id"), (String) row.get("idp_alias"),
                    (String) row.get("external_subject"), (String) row.get("user_id")));
            if (r != null) {
                done.add(r);
            }
        }
        return done;
    }

    private Resolution resolve(final String id, final String alias, final String subject, final String userId) {
        final List<Map<String, Object>> owners = jdbc.queryForList(
                "SELECT DISTINCT realm_id, lower(protocol) AS protocol FROM identity_provider WHERE alias = ?", alias);
        final long realms = owners.stream().map(o -> o.get("realm_id")).distinct().count();
        if (realms == 1) {
            final String realm = (String) owners.get(0).get("realm_id");
            final String protocol = String.valueOf(owners.get(0).get("protocol"));
            final String via = List.of("eudi-wallet", "openid4vp", "wallet").contains(protocol)
                    ? LinkProvenance.WALLET : LinkProvenance.LEGACY;
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
