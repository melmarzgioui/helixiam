/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet.trust.tl;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.helixiam.authorization.federation.wallet.trust.tl.TrustedListSource.Member;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionTemplate;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * {@code trusted_list_source} over plain JDBC. Every write commits in its own transaction (the pool runs with
 * auto-commit off) and bumps {@code version}, which {@link TrustedListService#sync} compares to reload what moved.
 * Refresh results are written only by the lease holder ({@link #tryLease}, a conditional update, so exactly one
 * replica refreshes a source at a time).
 */
public class TrustedListRepository {

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final TypeReference<List<String>> STRINGS = new TypeReference<>() {
    };
    private static final String COLUMNS = "id, realm_id, name, url, format, signer_certificates, service_types, "
            + "accepted_statuses, territories, grace_hours, enabled, status, last_attempt_at, last_success_at, "
            + "list_issued_at, next_update, next_refresh_at, sequence_number, lists_read, last_error, services_json, "
            + "version, config_version, list_of_lists, created_at, updated_at";
    private static final String MEMBER_COLUMNS = "source_id, member_key, location, territory, status, services_json, "
            + "sequence_number, list_issued_at, next_update, last_attempt_at, last_success_at, last_error, version";

    private final JdbcTemplate jdbc;
    private final TransactionTemplate tx;
    private final TransactionTemplate readTx;

    public TrustedListRepository(final JdbcTemplate jdbc, final PlatformTransactionManager transactions) {
        this.jdbc = jdbc;
        this.tx = new TransactionTemplate(transactions);
        this.tx.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
        this.readTx = new TransactionTemplate(transactions);
        this.readTx.setReadOnly(true);
    }

    public List<TrustedListSource> list(final String realmId) {
        return readTx.execute(s -> jdbc.query("SELECT " + COLUMNS + " FROM trusted_list_source WHERE realm_id = ? "
                + "ORDER BY name", MAPPER, realmId));
    }

    public List<TrustedListSource> all() {
        return readTx.execute(s -> jdbc.query("SELECT " + COLUMNS + " FROM trusted_list_source", MAPPER));
    }

    public Optional<TrustedListSource> get(final String realmId, final String id) {
        return first(readTx.execute(s -> jdbc.query("SELECT " + COLUMNS
                + " FROM trusted_list_source WHERE realm_id = ? AND id = ?", MAPPER, realmId, id)));
    }

    public Optional<TrustedListSource> byId(final String id) {
        return first(readTx.execute(s -> jdbc.query("SELECT " + COLUMNS + " FROM trusted_list_source WHERE id = ?",
                MAPPER, id)));
    }

    public Optional<TrustedListSource> byName(final String realmId, final String name) {
        return first(readTx.execute(s -> jdbc.query("SELECT " + COLUMNS
                + " FROM trusted_list_source WHERE realm_id = ? AND name = ?", MAPPER, realmId, name)));
    }

    /** id → version of every source (one small query per poll). */
    public Map<String, Long> versions() {
        final Map<String, Long> out = new LinkedHashMap<>();
        readTx.executeWithoutResult(s -> jdbc.query("SELECT id, version FROM trusted_list_source",
                rs -> {
                    out.put(rs.getString(1), rs.getLong(2));
                }));
        return out;
    }

    /** Enabled sources whose next refresh is due (or never planned). */
    public List<TrustedListSource> due(final long now) {
        return readTx.execute(s -> jdbc.query("SELECT " + COLUMNS + " FROM trusted_list_source WHERE enabled = TRUE "
                + "AND (next_refresh_at IS NULL OR next_refresh_at <= ?)", MAPPER, now));
    }

    public void insert(final String id, final String realmId, final TrustedListSource.Config c, final long now) {
        tx.executeWithoutResult(s -> jdbc.update("INSERT INTO trusted_list_source (id, realm_id, name, url, format, "
                + "signer_certificates, service_types, accepted_statuses, territories, grace_hours, enabled, status, "
                + "version, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)",
                id, realmId, c.name(), c.url(), c.format().name(), c.signerCertificates(), json(c.serviceTypes()),
                json(c.acceptedStatuses()), json(c.territories()), c.graceHours(), c.enabled(),
                TrustedListHealth.Status.NEVER.name(), now, now));
    }

    /**
     * Saves the settings. When {@code resetState} (the list itself changed), the last good services and the refresh
     * state are dropped and the source is due at once: anchors extracted under other settings never survive.
     */
    public boolean updateConfig(final String realmId, final String id, final TrustedListSource.Config c,
                                final boolean resetState, final long now) {
        final String reset = resetState ? ", status = 'NEVER', last_attempt_at = NULL, last_success_at = NULL, "
                + "list_issued_at = NULL, next_update = NULL, next_refresh_at = NULL, sequence_number = NULL, "
                + "lists_read = NULL, last_error = NULL, services_json = NULL, list_of_lists = FALSE" : "";
        final Integer n = tx.execute(s -> resetMembers(resetState, id) + jdbc.update("UPDATE trusted_list_source SET name = ?, url = ?, format = ?, "
                + "signer_certificates = ?, service_types = ?, accepted_statuses = ?, territories = ?, "
                + "grace_hours = ?, enabled = ?, version = version + 1, config_version = config_version + 1, "
                + "lease_owner = NULL, lease_until = NULL, updated_at = ?" + reset
                + " WHERE realm_id = ? AND id = ?", c.name(), c.url(), c.format().name(), c.signerCertificates(),
                json(c.serviceTypes()), json(c.acceptedStatuses()), json(c.territories()), c.graceHours(),
                c.enabled(), now, realmId, id));
        return n != null && n == 1;
    }

    public boolean delete(final String realmId, final String id) {
        final Integer n = tx.execute(s -> jdbc.update("DELETE FROM trusted_list_source WHERE realm_id = ? AND id = ?",
                realmId, id));
        return n != null && n == 1;
    }

    /**
     * Takes the refresh lease of {@code id} until {@code until} when no lease is running. Not re-entrant: a second
     * refresh on the same replica (the console while the scheduler runs) is refused like one on another replica.
     */
    public boolean tryLease(final String id, final String owner, final long now, final long until) {
        final Integer n = tx.execute(s -> jdbc.update("UPDATE trusted_list_source SET lease_owner = ?, lease_until = ? "
                + "WHERE id = ? AND (lease_owner IS NULL OR lease_until IS NULL OR lease_until < ?)",
                owner, until, id, now));
        return n != null && n == 1;
    }

    /** Extends a running lease; false when it was lost (taken over, or cleared by a settings change). */
    public boolean renewLease(final String id, final String owner, final long configVersion, final long until) {
        final Integer n = tx.execute(s -> jdbc.update("UPDATE trusted_list_source SET lease_until = ? "
                + "WHERE id = ? AND lease_owner = ? AND config_version = ?", until, id, owner, configVersion));
        return n != null && n == 1;
    }

    /** Gives a lease back (no-op when it is not held by {@code owner} any more). */
    public void releaseLease(final String id, final String owner) {
        tx.executeWithoutResult(s -> jdbc.update("UPDATE trusted_list_source SET lease_owner = NULL, lease_until = NULL "
                + "WHERE id = ? AND lease_owner = ?", id, owner));
    }

    /**
     * Stores a verified list and releases the lease, only while {@code owner} still holds the lease, the settings are
     * still those of {@code configVersion}, and the sequence number does not go down (rollback, enforced here too).
     * False means the result was dropped.
     */
    public boolean recordSuccess(final String id, final String owner, final long configVersion, final LoadedList loaded,
                                 final String servicesJson, final long now, final long nextRefreshAt) {
        final Integer n = tx.execute(s -> jdbc.update("UPDATE trusted_list_source SET status = ?, last_attempt_at = ?, "
                + "last_success_at = ?, list_issued_at = ?, next_update = ?, next_refresh_at = ?, sequence_number = ?, "
                + "lists_read = ?, last_error = NULL, services_json = ?, list_of_lists = FALSE, version = version + 1, "
                + "lease_owner = NULL, lease_until = NULL WHERE id = ? AND lease_owner = ? AND config_version = ? "
                + "AND (sequence_number IS NULL OR services_json IS NULL OR sequence_number <= ?)",
                TrustedListHealth.Status.OK.name(), now, now, loaded.issuedAt().toEpochMilli(),
                loaded.nextUpdate().toEpochMilli(), nextRefreshAt, loaded.sequence(), loaded.listsRead(),
                servicesJson, id, owner, configVersion, loaded.sequence()));
        return n != null && n == 1;
    }

    /** What to write for one member of a verified list of lists. */
    public record MemberWrite(LoadedList.Member member, String servicesJson, String failureStatus) {
    }

    /**
     * Stores a verified list of trusted lists, under the same conditions as {@link #recordSuccess}, and in the same
     * transaction its members: a loaded member replaces its last good state (never with a lower sequence number, also
     * checked here), a failed one keeps it and records the error, and members the list no longer points at (or that
     * the territories no longer select) are deleted. False means nothing was written.
     */
    public boolean recordListOfListsSuccess(final String id, final String owner, final long configVersion,
                                            final LoadedList loaded, final List<MemberWrite> members, final long now,
                                            final long nextRefreshAt) {
        final Boolean ok = tx.execute(s -> {
            final int n = jdbc.update("UPDATE trusted_list_source SET status = ?, last_attempt_at = ?, "
                    + "last_success_at = ?, list_issued_at = ?, next_update = ?, next_refresh_at = ?, "
                    + "sequence_number = ?, lists_read = ?, last_error = NULL, services_json = '[]', "
                    + "list_of_lists = TRUE, version = version + 1, lease_owner = NULL, lease_until = NULL "
                    + "WHERE id = ? AND lease_owner = ? AND config_version = ? "
                    + "AND (sequence_number IS NULL OR services_json IS NULL OR sequence_number <= ?)",
                    TrustedListHealth.Status.OK.name(), now, now, loaded.issuedAt().toEpochMilli(),
                    loaded.nextUpdate().toEpochMilli(), nextRefreshAt, loaded.sequence(), loaded.listsRead(), id,
                    owner, configVersion, loaded.sequence());
            if (n != 1) {
                return false;
            }
            final java.util.Set<String> keep = new java.util.HashSet<>();
            for (final MemberWrite w : members) {
                final LoadedList.Member m = w.member();
                keep.add(m.key());
                if (m.loaded()) {
                    jdbc.update("INSERT INTO trusted_list_member (" + MEMBER_COLUMNS + ") VALUES "
                            + "(?, ?, ?, ?, 'OK', ?, ?, ?, ?, ?, ?, NULL, 1) ON CONFLICT (source_id, member_key) DO "
                            + "UPDATE SET status = 'OK', services_json = EXCLUDED.services_json, "
                            + "sequence_number = EXCLUDED.sequence_number, list_issued_at = EXCLUDED.list_issued_at, "
                            + "next_update = EXCLUDED.next_update, last_attempt_at = EXCLUDED.last_attempt_at, "
                            + "last_success_at = EXCLUDED.last_success_at, last_error = NULL, "
                            + "version = trusted_list_member.version + 1 WHERE trusted_list_member.sequence_number IS "
                            + "NULL OR trusted_list_member.services_json IS NULL "
                            + "OR trusted_list_member.sequence_number <= EXCLUDED.sequence_number",
                            id, m.key(), m.location(), m.territory(), w.servicesJson(), m.sequence(),
                            m.issuedAt().toEpochMilli(), m.nextUpdate().toEpochMilli(), now, now);
                } else {
                    final String error = truncate(m.errorKind() + ": " + m.errorMessage());
                    jdbc.update("INSERT INTO trusted_list_member (" + MEMBER_COLUMNS + ") VALUES "
                            + "(?, ?, ?, ?, ?, NULL, NULL, NULL, NULL, ?, NULL, ?, 1) ON CONFLICT (source_id, "
                            + "member_key) DO UPDATE SET status = EXCLUDED.status, last_attempt_at = "
                            + "EXCLUDED.last_attempt_at, last_error = EXCLUDED.last_error, "
                            + "version = trusted_list_member.version + 1",
                            id, m.key(), m.location(), m.territory(), w.failureStatus(), now, error);
                }
            }
            for (final Member existing : jdbc.query("SELECT " + MEMBER_COLUMNS
                    + " FROM trusted_list_member WHERE source_id = ?", MEMBER_MAPPER, id)) {
                if (!keep.contains(existing.key())) {
                    jdbc.update("DELETE FROM trusted_list_member WHERE source_id = ? AND member_key = ?", id,
                            existing.key());
                }
            }
            return true;
        });
        return Boolean.TRUE.equals(ok);
    }

    /** The members of a list of trusted lists, in no particular order. */
    public List<Member> members(final String sourceId) {
        return readTx.execute(s -> jdbc.query("SELECT " + MEMBER_COLUMNS
                + " FROM trusted_list_member WHERE source_id = ? ORDER BY territory, location", MEMBER_MAPPER,
                sourceId));
    }

    /**
     * Moves a member's stored status to {@code status} only when it is still at {@code expectedVersion} and not
     * already there, and bumps the source's version so replicas reload; true for exactly one caller.
     */
    public boolean transitionMember(final String sourceId, final String key, final String status,
                                    final long expectedVersion, final long now) {
        final Boolean ok = tx.execute(s -> {
            final int n = jdbc.update("UPDATE trusted_list_member SET status = ?, version = version + 1 "
                    + "WHERE source_id = ? AND member_key = ? AND status <> ? AND version = ?", status, sourceId, key,
                    status, expectedVersion);
            if (n == 1) {
                jdbc.update("UPDATE trusted_list_source SET version = version + 1, updated_at = ? WHERE id = ?", now,
                        sourceId);
            }
            return n == 1;
        });
        return Boolean.TRUE.equals(ok);
    }

    private int resetMembers(final boolean reset, final String id) {
        if (reset) {
            jdbc.update("DELETE FROM trusted_list_member WHERE source_id = ?", id);
        }
        return 0;
    }

    /**
     * Records a failed refresh, keeping the last good services, and releases the lease; under the same lease and
     * settings conditions as {@link #recordSuccess}.
     */
    public boolean recordFailure(final String id, final String owner, final long configVersion, final String status,
                                 final String error, final long now, final long nextRefreshAt) {
        final Integer n = tx.execute(s -> jdbc.update("UPDATE trusted_list_source SET status = ?, last_attempt_at = ?, "
                + "last_error = ?, next_refresh_at = ?, version = version + 1, lease_owner = NULL, lease_until = NULL "
                + "WHERE id = ? AND lease_owner = ? AND config_version = ?", status, now, truncate(error),
                nextRefreshAt, id, owner, configVersion));
        return n != null && n == 1;
    }

    /**
     * Moves the stored status to {@code status} only when the row is still at {@code expectedVersion} (the state the
     * caller judged) and not already there; true for exactly one caller per transition (one replica audits it), never
     * over a newer refresh.
     */
    public boolean transition(final String id, final String status, final long expectedVersion, final long now) {
        final Integer n = tx.execute(s -> jdbc.update("UPDATE trusted_list_source SET status = ?, "
                + "version = version + 1, updated_at = ? WHERE id = ? AND status <> ? AND version = ?", status, now, id,
                status, expectedVersion));
        return n != null && n == 1;
    }

    private static String truncate(final String v) {
        return v == null || v.length() <= 1000 ? v : v.substring(0, 1000);
    }

    private static Optional<TrustedListSource> first(final List<TrustedListSource> rows) {
        return rows == null || rows.isEmpty() ? Optional.empty() : Optional.of(rows.get(0));
    }

    private static String json(final List<String> values) {
        try {
            return JSON.writeValueAsString(values);
        } catch (final JsonProcessingException e) {
            throw new IllegalStateException(e);
        }
    }

    private static List<String> strings(final String json) {
        try {
            return json == null ? List.of() : JSON.readValue(json, STRINGS);
        } catch (final JsonProcessingException e) {
            return List.of();
        }
    }

    private static Long longOrNull(final ResultSet rs, final String column) throws SQLException {
        final long v = rs.getLong(column);
        return rs.wasNull() ? null : v;
    }

    private static final RowMapper<Member> MEMBER_MAPPER = (rs, i) -> new Member(rs.getString("source_id"),
            rs.getString("member_key"), rs.getString("location"), rs.getString("territory"), rs.getString("status"),
            rs.getString("services_json"), longOrNull(rs, "sequence_number"), longOrNull(rs, "list_issued_at"),
            longOrNull(rs, "next_update"), longOrNull(rs, "last_attempt_at"), longOrNull(rs, "last_success_at"),
            rs.getString("last_error"), rs.getLong("version"));

    private static final RowMapper<TrustedListSource> MAPPER = (rs, i) -> {
        final TrustedListSpec.Format format;
        try {
            format = TrustedListSpec.Format.valueOf(rs.getString("format"));
        } catch (final IllegalArgumentException e) {
            throw new SQLException("unknown trusted list format", e);
        }
        final int read = rs.getInt("lists_read");
        final Integer listsRead = rs.wasNull() ? null : read;
        return new TrustedListSource(rs.getString("id"), rs.getString("realm_id"),
                new TrustedListSource.Config(rs.getString("name"), rs.getString("url"), format,
                        rs.getString("signer_certificates"), strings(rs.getString("service_types")),
                        strings(rs.getString("accepted_statuses")), strings(rs.getString("territories")),
                        rs.getInt("grace_hours"), rs.getBoolean("enabled")),
                new TrustedListSource.State(rs.getString("status"), longOrNull(rs, "last_attempt_at"),
                        longOrNull(rs, "last_success_at"), longOrNull(rs, "list_issued_at"),
                        longOrNull(rs, "next_update"), longOrNull(rs, "next_refresh_at"),
                        longOrNull(rs, "sequence_number"), listsRead,
                        rs.getString("last_error"), rs.getString("services_json"), rs.getLong("version"),
                        rs.getLong("config_version"), rs.getBoolean("list_of_lists"), rs.getLong("created_at"),
                        rs.getLong("updated_at")));
    };
}
