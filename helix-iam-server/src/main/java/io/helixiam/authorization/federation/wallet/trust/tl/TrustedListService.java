/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet.trust.tl;

import io.helixiam.authorization.federation.wallet.trust.TrustAnchors;
import io.helixiam.common.log.LogSafe;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * The trusted list sources of every realm (the {@code EuTrustedListSource} of the roadmap): their admin settings, the
 * refreshes that turn a published, signed list into verified anchors, and the anchors wallet providers read.
 *
 * <h2>Refresh: one replica at a time</h2>
 * {@link #refreshDue} (on a schedule) and {@link #refreshNow} (the console) take the source row's lease with a
 * conditional update ({@link TrustedListRepository#tryLease}); only the holder fetches and writes the result. A
 * verified list replaces the stored services and plans the next refresh at the earlier of the refresh interval and the
 * list's NextUpdate. A failure keeps the last good services (fail safe), records the reason and retries after the
 * retry interval. Every refresh, failure, and every move into STALE or EXPIRED is audited and logged.
 *
 * <h2>Anchors: every replica, from the database</h2>
 * Each replica keeps an in-memory copy of every source (verified services only) and reloads the rows whose
 * {@code version} moved ({@link #sync}, polled); so a refresh on one replica reaches the others within one poll. What
 * {@link #anchors} returns is decided at call time by {@link TrustedListHealth}: the last good services until their
 * NextUpdate plus the source's grace, then nothing (fail closed). Only CA certificates that pass
 * {@link TrustAnchors#trustAnchorProblem} are returned.
 */
public class TrustedListService implements TrustedListAnchorSource {

    private static final Logger LOG = LogManager.getLogger(TrustedListService.class);

    /** Audit types. */
    public static final String REFRESHED = "TRUSTED_LIST_REFRESHED";
    public static final String REFRESH_FAILED = "TRUSTED_LIST_REFRESH_FAILED";
    public static final String STALE = "TRUSTED_LIST_STALE";
    public static final String EXPIRED = "TRUSTED_LIST_EXPIRED";

    /** Where refresh events go (the audit log in production). */
    @FunctionalInterface
    public interface AuditSink {
        void emit(String realm, String type, String sourceId, String outcome, Map<String, String> detail);
    }

    /**
     * Timing.
     *
     * @param refreshInterval longest time between two refreshes of a healthy source
     * @param retryInterval   wait after a failed refresh
     * @param lease           how long a refresh may hold the source before another replica may take it over
     */
    public record Settings(Duration refreshInterval, Duration retryInterval, Duration lease) {
        public static final Settings DEFAULTS = new Settings(Duration.ofHours(6), Duration.ofMinutes(15),
                Duration.ofMinutes(5));
    }

    /** Another replica (or request) is refreshing the source right now. */
    public static class RefreshBusyException extends RuntimeException {
        public RefreshBusyException() {
            super("A refresh of this trusted list is already running", null, false, false);
        }
    }

    /** The admin settings are not acceptable: field → message. */
    public static class InvalidConfigException extends RuntimeException {
        private final Map<String, String> fieldErrors;

        public InvalidConfigException(final Map<String, String> fieldErrors) {
            super("The trusted list settings are not valid", null, false, false);
            this.fieldErrors = Map.copyOf(fieldErrors);
        }

        public Map<String, String> fieldErrors() {
            return fieldErrors;
        }
    }

    private record Snapshot(TrustedListSource source, List<ListedService> services) {
    }

    private final TrustedListRepository repository;
    private final TrustedListLoader loader;
    private final AuditSink audit;
    private final Clock clock;
    private final Settings settings;
    private final String owner = "helix-" + UUID.randomUUID();
    private final Map<String, Snapshot> snapshots = new ConcurrentHashMap<>();

    public TrustedListService(final TrustedListRepository repository, final TrustedListLoader loader,
                              final AuditSink audit, final Clock clock, final Settings settings) {
        this.repository = Objects.requireNonNull(repository, "repository");
        this.loader = Objects.requireNonNull(loader, "loader");
        this.audit = Objects.requireNonNull(audit, "audit");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.settings = Objects.requireNonNull(settings, "settings");
    }

    // ------------------------------------------------------------------------------------------------ admin

    public List<TrustedListSource> list(final String realmId) {
        return repository.list(realmId);
    }

    public Optional<TrustedListSource> get(final String realmId, final String id) {
        return repository.get(realmId, id);
    }

    /** The last good services of a source (whatever its status now), for the console's preview. */
    public List<ListedService> services(final TrustedListSource source) {
        return ServicesCodec.decode(source.state().servicesJson());
    }

    /** The status of {@code source} now. */
    public TrustedListHealth.Status status(final TrustedListSource source) {
        return TrustedListHealth.evaluate(source, clock.instant());
    }

    /** @throws InvalidConfigException for bad settings or a name already used in the realm */
    public TrustedListSource create(final String realmId, final TrustedListSource.Config config) {
        final TrustedListSource.Config c = normalize(config);
        final Map<String, String> errors = new LinkedHashMap<>(TrustedListConfigValidator.validate(c));
        if (!errors.containsKey("name") && repository.byName(realmId, c.name()).isPresent()) {
            errors.put("name", "A trusted list named '" + c.name() + "' already exists in this realm");
        }
        if (!errors.isEmpty()) {
            throw new InvalidConfigException(errors);
        }
        final String id = UUID.randomUUID().toString();
        repository.insert(id, realmId, c, clock.millis());
        sync();
        return repository.get(realmId, id).orElseThrow();
    }

    /**
     * Saves new settings. A change to what is loaded (URL, format, signers, types, statuses, territories) drops the
     * stored anchors at once and makes the source due: anchors extracted under other settings never survive.
     *
     * @return the source, or empty when it does not exist in the realm
     */
    public Optional<TrustedListSource> update(final String realmId, final String id,
                                              final TrustedListSource.Config config) {
        final Optional<TrustedListSource> existing = repository.get(realmId, id);
        if (existing.isEmpty()) {
            return Optional.empty();
        }
        final TrustedListSource.Config c = normalize(config);
        final Map<String, String> errors = new LinkedHashMap<>(TrustedListConfigValidator.validate(c));
        if (!errors.containsKey("name") && !c.name().equals(existing.get().config().name())
                && repository.byName(realmId, c.name()).isPresent()) {
            errors.put("name", "A trusted list named '" + c.name() + "' already exists in this realm");
        }
        if (!errors.isEmpty()) {
            throw new InvalidConfigException(errors);
        }
        repository.updateConfig(realmId, id, c, !existing.get().config().sameList(c), clock.millis());
        sync();
        return repository.get(realmId, id);
    }

    public boolean delete(final String realmId, final String id) {
        final boolean deleted = repository.delete(realmId, id);
        sync();
        return deleted;
    }

    /**
     * Refreshes one source now (the console's "Refresh now").
     *
     * @return the source after the attempt (its state says whether it succeeded), or empty when it does not exist
     * @throws RefreshBusyException when another refresh of it holds the lease
     */
    public Optional<TrustedListSource> refreshNow(final String realmId, final String id) {
        final Optional<TrustedListSource> source = repository.get(realmId, id);
        if (source.isEmpty()) {
            return source;
        }
        if (!refresh(source.get())) {
            throw new RefreshBusyException();
        }
        return repository.get(realmId, id);
    }

    // ------------------------------------------------------------------------------------------------ schedule

    /** One scheduler step: reload what moved, refresh what is due, record expiries. Never throws. */
    public void tick() {
        try {
            sync();
            refreshDue();
            checkHealth();
        } catch (final RuntimeException e) {
            LOG.warn("trusted lists: scheduled step failed: {}", e.getClass().getSimpleName());
        }
    }

    /** Refreshes every enabled source that is due, each under its lease. Returns how many this replica refreshed. */
    public int refreshDue() {
        int refreshed = 0;
        for (final TrustedListSource source : repository.due(clock.millis())) {
            if (refresh(source)) {
                refreshed++;
            }
        }
        return refreshed;
    }

    /**
     * Records (once, on whichever replica wins the conditional update) a source whose last good list went STALE or
     * EXPIRED by time alone, and audits it.
     */
    public void checkHealth() {
        final Instant now = clock.instant();
        for (final Snapshot snapshot : snapshots.values()) {
            final TrustedListSource source = snapshot.source();
            final TrustedListHealth.Status status = TrustedListHealth.evaluate(source, now);
            if ((status == TrustedListHealth.Status.STALE || status == TrustedListHealth.Status.EXPIRED)
                    && !status.name().equals(source.state().status())
                    && repository.transition(source.id(), status.name(), now.toEpochMilli())) {
                final Map<String, String> detail = detail(source);
                detail.put("nextUpdate", instant(source.state().nextUpdate()));
                detail.put("graceHours", String.valueOf(source.config().graceHours()));
                if (status == TrustedListHealth.Status.EXPIRED) {
                    LOG.error("trusted lists: {} of realm {} EXPIRED (NextUpdate {} plus {} h grace passed): its "
                                    + "anchors are no longer used", LogSafe.sanitize(source.config().name()),
                            LogSafe.sanitize(source.realmId()), detail.get("nextUpdate"), source.config().graceHours());
                    audit.emit(source.realmId(), EXPIRED, source.id(), "FAILURE", detail);
                } else {
                    LOG.warn("trusted lists: {} of realm {} is STALE (NextUpdate {} passed); its anchors are used for "
                                    + "{} h more", LogSafe.sanitize(source.config().name()),
                            LogSafe.sanitize(source.realmId()), detail.get("nextUpdate"), source.config().graceHours());
                    audit.emit(source.realmId(), STALE, source.id(), "FAILURE", detail);
                }
            }
        }
        sync();
    }

    /**
     * Reloads the sources whose version moved (and drops deleted ones). Returns how many were reloaded. Every replica
     * runs it on a poll, so a refresh or edit on one reaches all.
     */
    public synchronized int sync() {
        final Map<String, Long> versions = repository.versions();
        int reloaded = 0;
        for (final Map.Entry<String, Long> v : versions.entrySet()) {
            final Snapshot have = snapshots.get(v.getKey());
            if (have != null && have.source().state().version() == v.getValue()) {
                continue;
            }
            final Optional<TrustedListSource> row = repository.byId(v.getKey());
            if (row.isPresent()) {
                snapshots.put(v.getKey(), new Snapshot(row.get(), ServicesCodec.decode(row.get().state().servicesJson())));
                reloaded++;
            }
        }
        snapshots.keySet().removeIf(id -> !versions.containsKey(id));
        return reloaded;
    }

    // ------------------------------------------------------------------------------------------------ anchors

    @Override
    public List<X509Certificate> anchors(final String realm, final List<String> sources,
                                         final List<String> serviceTypes) {
        if (sources == null || sources.isEmpty()) {
            return List.of();
        }
        final Set<String> names = new HashSet<>(sources);
        final Set<String> types = serviceTypes == null ? Set.of() : new HashSet<>(serviceTypes);
        final Instant now = clock.instant();
        final List<X509Certificate> out = new ArrayList<>();
        for (final Snapshot snapshot : snapshots.values()) {
            final TrustedListSource source = snapshot.source();
            if (!source.realmId().equals(realm) || !names.contains(source.config().name())
                    || !TrustedListHealth.evaluate(source, now).anchorsUsable()) {
                continue;
            }
            for (final ListedService service : snapshot.services()) {
                if ((types.isEmpty() || types.contains(service.serviceType()))
                        && TrustAnchors.trustAnchorProblem(service.certificate()) == null
                        && !out.contains(service.certificate())) {
                    out.add(service.certificate());
                }
            }
        }
        return out;
    }

    @Override
    public boolean exists(final String realm, final String name) {
        return snapshots.values().stream().anyMatch(s -> s.source().realmId().equals(realm)
                && s.source().config().name().equals(name)) || repository.byName(realm, name).isPresent();
    }

    // ------------------------------------------------------------------------------------------------ refresh

    /** One refresh under the lease; false when another holder has it. */
    private boolean refresh(final TrustedListSource source) {
        final Instant now = clock.instant();
        if (!repository.tryLease(source.id(), owner, now.toEpochMilli(),
                now.plus(settings.lease()).toEpochMilli())) {
            return false;
        }
        final Map<String, String> detail = detail(source);
        try {
            final LoadedList loaded = loader.load(spec(source), source.realmId());
            final Instant planned = now.plus(settings.refreshInterval());
            final Instant next = loaded.nextUpdate().isBefore(planned) ? loaded.nextUpdate() : planned;
            final long nextRefresh = Math.max(next.toEpochMilli(), now.plus(Duration.ofMinutes(1)).toEpochMilli());
            repository.recordSuccess(source.id(), owner, loaded, ServicesCodec.encode(loaded.services()),
                    now.toEpochMilli(), nextRefresh);
            final long usable = loaded.services().stream()
                    .filter(s -> TrustAnchors.trustAnchorProblem(s.certificate()) == null).count();
            detail.put("services", String.valueOf(loaded.services().size()));
            detail.put("anchors", String.valueOf(usable));
            detail.put("lists", String.valueOf(loaded.listsRead()));
            detail.put("sequence", String.valueOf(loaded.sequence()));
            detail.put("nextUpdate", loaded.nextUpdate().toString());
            LOG.info("trusted lists: {} of realm {} refreshed: {} lists verified, {} services ({} usable anchors), "
                            + "sequence {}, NextUpdate {}", LogSafe.sanitize(source.config().name()),
                    LogSafe.sanitize(source.realmId()), loaded.listsRead(), loaded.services().size(), usable,
                    loaded.sequence(), loaded.nextUpdate());
            audit.emit(source.realmId(), REFRESHED, source.id(), "SUCCESS", detail);
        } catch (final TrustedListException e) {
            failed(source, now, e.kind().name(), e.getMessage(), detail);
        } catch (final RuntimeException e) {
            failed(source, now, "INTERNAL", "unexpected error: " + e.getClass().getSimpleName(), detail);
        } finally {
            sync();
        }
        return true;
    }

    private void failed(final TrustedListSource source, final Instant now, final String kind, final String message,
                        final Map<String, String> detail) {
        final boolean hadGood = source.state().servicesJson() != null && source.state().nextUpdate() != null;
        final TrustedListHealth.Status status = TrustedListHealth.evaluate(source.config().enabled(),
                hadGood ? Instant.ofEpochMilli(source.state().nextUpdate()) : null,
                Duration.ofHours(source.config().graceHours()), true, true, now);
        repository.recordFailure(source.id(), owner, status.name(), kind + ": " + message, now.toEpochMilli(),
                now.plus(settings.retryInterval()).toEpochMilli());
        detail.put("reason", kind);
        detail.put("message", message);
        detail.put("status", status.name());
        if (hadGood && status.anchorsUsable()) {
            detail.put("anchorsKeptUntil", Instant.ofEpochMilli(source.state().nextUpdate())
                    .plus(Duration.ofHours(source.config().graceHours())).toString());
        }
        LOG.warn("trusted lists: refresh of {} of realm {} failed ({}: {}); status {}{}",
                LogSafe.sanitize(source.config().name()), LogSafe.sanitize(source.realmId()), kind,
                LogSafe.sanitize(message), status, status.anchorsUsable()
                        ? ", the last good anchors are kept until " + detail.get("anchorsKeptUntil")
                        : ", no anchors are in use");
        audit.emit(source.realmId(), REFRESH_FAILED, source.id(), "FAILURE", detail);
    }

    private static TrustedListSpec spec(final TrustedListSource source) {
        final TrustedListSource.Config c = source.config();
        final List<X509Certificate> signers;
        try {
            signers = PemCertificates.parse(c.signerCertificates());
        } catch (final IllegalArgumentException e) {
            throw new IllegalStateException("stored signer certificates cannot be read");
        }
        final boolean hadGood = source.state().servicesJson() != null;
        return new TrustedListSpec(c.url(), c.format(), signers, Set.copyOf(c.serviceTypes()),
                Set.copyOf(c.acceptedStatuses()), Set.copyOf(c.territories()),
                hadGood ? source.state().sequenceNumber() : null);
    }

    private static Map<String, String> detail(final TrustedListSource source) {
        final Map<String, String> d = new LinkedHashMap<>();
        d.put("name", source.config().name());
        d.put("url", source.config().url());
        return d;
    }

    private static String instant(final Long millis) {
        return millis == null ? "" : Instant.ofEpochMilli(millis).toString();
    }

    private static TrustedListSource.Config normalize(final TrustedListSource.Config c) {
        return new TrustedListSource.Config(c.name() == null ? null : c.name().trim(),
                c.url() == null ? null : c.url().trim(), c.format(), c.signerCertificates(),
                trimmed(c.serviceTypes()), trimmed(c.acceptedStatuses()), trimmed(c.territories()), c.graceHours(),
                c.enabled());
    }

    private static List<String> trimmed(final List<String> values) {
        return values.stream().filter(Objects::nonNull).map(String::trim).filter(v -> !v.isEmpty()).toList();
    }
}
