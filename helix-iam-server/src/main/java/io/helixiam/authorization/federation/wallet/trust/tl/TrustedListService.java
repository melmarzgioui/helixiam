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
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

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
    public static final String DISCARDED = "TRUSTED_LIST_REFRESH_DISCARDED";
    public static final String INTEGRITY_FAILED = "TRUSTED_LIST_INTEGRITY_FAILED";
    public static final String SIGNER_EXPIRING = "TRUSTED_LIST_SIGNER_EXPIRING";
    public static final String SIGNER_EXPIRED = "TRUSTED_LIST_SIGNER_EXPIRED";
    /** A pinned signer expiring within this is audited at every refresh (and shown in the console). */
    public static final Duration SIGNER_WARNING = Duration.ofDays(30);
    public static final String MEMBER_REFRESH_FAILED = "TRUSTED_LIST_MEMBER_REFRESH_FAILED";
    public static final String MEMBER_STALE = "TRUSTED_LIST_MEMBER_STALE";
    public static final String MEMBER_EXPIRED = "TRUSTED_LIST_MEMBER_EXPIRED";

    /** Renews the leases of running refreshes (one daemon thread for every service instance). */
    private static final ScheduledExecutorService LEASE_KEEPER = Executors.newSingleThreadScheduledExecutor(r -> {
        final Thread t = new Thread(r, "helix-trusted-list-lease");
        t.setDaemon(true);
        return t;
    });

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
     * @param lease           how long a lease lasts without renewal; a running refresh renews it every third of it,
     *                        so only a replica that died (or hung) loses it
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

    private record MemberSnapshot(TrustedListSource.Member member, List<ListedService> services) {
    }

    private record Snapshot(TrustedListSource source, List<ListedService> services, List<MemberSnapshot> members) {
    }

    private final TrustedListRepository repository;
    private final TrustedListLoader loader;
    private final AuditSink audit;
    private final Clock clock;
    private final Settings settings;
    private final String owner = "helix-" + UUID.randomUUID();
    private final Map<String, Snapshot> snapshots = new ConcurrentHashMap<>();

    private final TrustedListIntegrity integrity;
    /** Whether sources may be saved without a MAC key (the dev profile only). */
    private final boolean allowWithoutIntegrity;
    /** (source id, version) pairs whose integrity failure this replica already reported. */
    private final Set<String> reportedTampering = ConcurrentHashMap.newKeySet();

    /** Without integrity MACs: only for a dev deployment without DB_ENCRYPTION (and tests). */
    public TrustedListService(final TrustedListRepository repository, final TrustedListLoader loader,
                              final AuditSink audit, final Clock clock, final Settings settings) {
        this(repository, loader, audit, clock, settings, TrustedListIntegrity.none(), true);
    }

    /**
     * @param integrity             MACs keyed from DB_ENCRYPTION over settings and stored anchors
     * @param allowWithoutIntegrity whether a source may be saved when {@code integrity} has no key (dev only)
     */
    public TrustedListService(final TrustedListRepository repository, final TrustedListLoader loader,
                              final AuditSink audit, final Clock clock, final Settings settings,
                              final TrustedListIntegrity integrity, final boolean allowWithoutIntegrity) {
        this.integrity = Objects.requireNonNull(integrity, "integrity");
        this.allowWithoutIntegrity = allowWithoutIntegrity;
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

    /**
     * The last good services of a source (whatever its status now), for the console's preview; for a list of
     * trusted lists, those of every member.
     */
    public List<ListedService> services(final TrustedListSource source) {
        if (!settingsIntact(source) || !servicesIntact(source)) {
            return List.of();
        }
        if (!source.state().listOfLists()) {
            return ServicesCodec.decode(source.state().servicesJson());
        }
        final List<ListedService> out = new ArrayList<>();
        for (final TrustedListSource.Member m : repository.members(source.id())) {
            if (memberIntact(m)) {
                out.addAll(ServicesCodec.decode(m.servicesJson()));
            }
        }
        return out;
    }

    /** Decodes stored services (for views); unreadable rows give none. */
    public static List<ListedService> decode(final String servicesJson) {
        return ServicesCodec.decode(servicesJson);
    }

    /** The members of a list of trusted lists (empty for a single list). */
    public List<TrustedListSource.Member> members(final TrustedListSource source) {
        return source.state().listOfLists() ? repository.members(source.id()) : List.of();
    }

    /** The status of one member now. */
    public TrustedListHealth.Status memberStatus(final TrustedListSource source, final TrustedListSource.Member m) {
        return TrustedListHealth.evaluate(source, m, clock.instant());
    }

    /**
     * The status of {@code source} now: its own (the list, or the list of lists), or {@code DEGRADED} for a healthy
     * list of lists some of whose members are not.
     */
    public TrustedListHealth.Status status(final TrustedListSource source) {
        return aggregate(source, members(source));
    }

    private TrustedListHealth.Status aggregate(final TrustedListSource source,
                                               final List<TrustedListSource.Member> members) {
        final Instant now = clock.instant();
        final TrustedListHealth.Status own = TrustedListHealth.evaluate(source, now);
        if (own == TrustedListHealth.Status.OK && members.stream()
                .anyMatch(m -> TrustedListHealth.evaluate(source, m, now) != TrustedListHealth.Status.OK)) {
            return TrustedListHealth.Status.DEGRADED;
        }
        return own;
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
        requireIntegrity();
        final String id = UUID.randomUUID().toString();
        repository.insert(id, realmId, c, clock.millis(), settingsMac(id, realmId, c));
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
        requireIntegrity();
        repository.updateConfig(realmId, id, c, !existing.get().config().sameList(c), clock.millis(),
                settingsMac(id, realmId, c));
        sync();
        return repository.get(realmId, id);
    }

    private void requireIntegrity() {
        if (!integrity.enabled() && !allowWithoutIntegrity) {
            throw new InvalidConfigException(Map.of("signerCertificates", "Database encryption is not configured: "
                    + "set DB_ENCRYPTION before adding trusted lists (their pinned signers and anchors are "
                    + "integrity-protected with it)"));
        }
    }

    // ------------------------------------------------------------------------------------------------ integrity

    private String settingsMac(final String id, final String realm, final TrustedListSource.Config c) {
        return integrity.mac("settings", id, realm, c.url(), c.format().name(), c.signerCertificates(),
                TrustedListRepository.settingJson(c.serviceTypes()),
                TrustedListRepository.settingJson(c.acceptedStatuses()),
                TrustedListRepository.settingJson(c.territories()));
    }

    private String servicesMac(final String id, final String servicesJson, final long sequence,
                               final long nextUpdate, final boolean listOfLists) {
        return integrity.mac("services", id, servicesJson, sequence, nextUpdate, listOfLists);
    }

    private String memberMac(final String sourceId, final String key, final String servicesJson, final long sequence,
                             final long nextUpdate) {
        return integrity.mac("member", sourceId, key, servicesJson, sequence, nextUpdate);
    }

    private boolean settingsIntact(final TrustedListSource s) {
        return integrity.verify(s.state().settingsMac(), "settings", s.id(), s.realmId(), s.config().url(),
                s.config().format().name(), s.config().signerCertificates(),
                TrustedListRepository.settingJson(s.config().serviceTypes()),
                TrustedListRepository.settingJson(s.config().acceptedStatuses()),
                TrustedListRepository.settingJson(s.config().territories()));
    }

    private boolean servicesIntact(final TrustedListSource s) {
        final TrustedListSource.State st = s.state();
        return st.servicesJson() == null || integrity.verify(st.servicesMac(), "services", s.id(), st.servicesJson(),
                st.sequenceNumber(), st.nextUpdate(), st.listOfLists());
    }

    private boolean memberIntact(final TrustedListSource.Member m) {
        return m.servicesJson() == null || integrity.verify(m.servicesMac(), "member", m.sourceId(), m.key(),
                m.servicesJson(), m.sequenceNumber(), m.nextUpdate());
    }

    /** Logs and audits (once per row version on this replica) a row that failed its integrity check. */
    private void reportTampering(final TrustedListSource source, final String what) {
        if (!reportedTampering.add(source.id() + "@" + source.state().version() + "@" + what)) {
            return;
        }
        final Map<String, String> detail = detail(source);
        detail.put("reason", "INTEGRITY");
        detail.put("message", what + " failed the integrity check; not used");
        LOG.error("trusted lists: {} of {} of realm {} failed the integrity check (modified outside HelixIAM, or "
                        + "DB_ENCRYPTION changed): not used; re-save the settings and refresh", what,
                LogSafe.sanitize(source.config().name()), LogSafe.sanitize(source.realmId()));
        audit.emit(source.realmId(), INTEGRITY_FAILED, source.id(), "FAILURE", detail);
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
        if (!refresh(source.get().id())) {
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
            if (refresh(source.id())) {
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
                    && repository.transition(source.id(), status.name(), source.state().version(),
                            now.toEpochMilli())) {
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
            for (final MemberSnapshot ms : snapshot.members()) {
                final TrustedListSource.Member m = ms.member();
                final TrustedListHealth.Status ownStatus = TrustedListHealth.evaluate(source, m, now);
                if ((ownStatus == TrustedListHealth.Status.STALE || ownStatus == TrustedListHealth.Status.EXPIRED)
                        && !ownStatus.name().equals(m.status())
                        && repository.transitionMember(source.id(), m.key(), ownStatus.name(), m.version(),
                                now.toEpochMilli())) {
                    final Map<String, String> detail = memberDetail(source, m);
                    detail.put("nextUpdate", instant(m.nextUpdate()));
                    detail.put("graceHours", String.valueOf(source.config().graceHours()));
                    final boolean expired = ownStatus == TrustedListHealth.Status.EXPIRED;
                    LOG.warn("trusted lists: member {} ({}) of {} of realm {} is {}", LogSafe.sanitize(m.territory()),
                            LogSafe.sanitize(m.location()), LogSafe.sanitize(source.config().name()),
                            LogSafe.sanitize(source.realmId()), expired ? "EXPIRED: its anchors are no longer used"
                                    : "STALE: its last good anchors are used within the grace period");
                    audit.emit(source.realmId(), expired ? MEMBER_EXPIRED : MEMBER_STALE, source.id(), "FAILURE",
                            detail);
                }
            }
        }
        sync();
    }

    private static Map<String, String> memberDetail(final TrustedListSource source, final TrustedListSource.Member m) {
        final Map<String, String> d = detail(source);
        d.put("territory", m.territory() == null ? "" : m.territory());
        d.put("memberUrl", m.location());
        return d;
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
                final TrustedListSource source = row.get();
                // a row whose MAC does not match is not used: no anchors from it (fail closed)
                final boolean intact = settingsIntact(source) && servicesIntact(source);
                if (!intact) {
                    reportTampering(source, settingsIntact(source) ? "the stored anchors" : "the stored settings");
                }
                final List<MemberSnapshot> members = new ArrayList<>();
                if (intact && source.state().listOfLists()) {
                    for (final TrustedListSource.Member m : repository.members(source.id())) {
                        if (memberIntact(m)) {
                            members.add(new MemberSnapshot(m, ServicesCodec.decode(m.servicesJson())));
                        } else {
                            reportTampering(source, "the stored anchors of member " + m.territory());
                        }
                    }
                }
                snapshots.put(v.getKey(), new Snapshot(source,
                        intact ? ServicesCodec.decode(source.state().servicesJson()) : List.of(), List.copyOf(members)));
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
            final List<ListedService> usable = new ArrayList<>();
            if (source.state().listOfLists()) {
                // each member counts only within its own NextUpdate plus grace
                for (final MemberSnapshot m : snapshot.members()) {
                    if (TrustedListHealth.evaluate(source, m.member(), now).anchorsUsable()) {
                        usable.addAll(m.services());
                    }
                }
            } else {
                usable.addAll(snapshot.services());
            }
            for (final ListedService service : usable) {
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

    /**
     * One refresh under the lease; false when another holder (another replica, or this one) has it. The row is read
     * again after the lease is taken, so the refresh runs with the settings in force, and its result is stored only
     * while the lease and those settings ({@code config_version}) still hold: a refresh overtaken by a settings change
     * is dropped and audited as {@link #DISCARDED}, never as a success. The lease is renewed while the load runs.
     */
    private boolean refresh(final String id) {
        final Instant now = clock.instant();
        if (!repository.tryLease(id, owner, now.toEpochMilli(), now.plus(settings.lease()).toEpochMilli())) {
            return false;
        }
        final Optional<TrustedListSource> row = repository.byId(id);
        if (row.isEmpty()) {
            return true; // deleted meanwhile
        }
        final TrustedListSource source = row.get();
        final long configVersion = source.state().configVersion();
        final long renewEvery = Math.max(100, settings.lease().toMillis() / 3);
        final ScheduledFuture<?> keeper = LEASE_KEEPER.scheduleAtFixedRate(() -> {
            try {
                repository.renewLease(id, owner, configVersion, clock.millis() + settings.lease().toMillis());
            } catch (final RuntimeException e) {
                LOG.debug("trusted lists: lease renewal failed: {}", e.getClass().getSimpleName());
            }
        }, renewEvery, renewEvery, TimeUnit.MILLISECONDS);
        final Map<String, String> detail = detail(source);
        try {
            if (!settingsIntact(source) || !servicesIntact(source)
                    || members(source).stream().anyMatch(m -> !memberIntact(m))) {
                failed(source, configVersion, now, "INTEGRITY", "the stored settings or anchors failed the integrity "
                        + "check (modified outside HelixIAM, or DB_ENCRYPTION changed); re-save the settings", detail);
                return true;
            }
            final LoadedList loaded;
            try {
                loaded = loader.load(spec(source), source.realmId());
            } catch (final TrustedListException e) {
                failed(source, configVersion, now, e.kind().name(), e.getMessage(), detail);
                return true;
            } catch (final RuntimeException e) {
                failed(source, configVersion, now, "INTERNAL", "unexpected error: " + e.getClass().getSimpleName(),
                        detail);
                return true;
            }
            final Instant planned = now.plus(settings.refreshInterval());
            final Instant next = loaded.nextUpdate().isBefore(planned) ? loaded.nextUpdate() : planned;
            final long nextRefresh = Math.max(next.toEpochMilli(), now.plus(Duration.ofMinutes(1)).toEpochMilli());
            final List<TrustedListSource.Member> before = loaded.listOfLists() ? repository.members(id) : List.of();
            final boolean stored = loaded.listOfLists()
                    ? repository.recordListOfListsSuccess(id, owner, configVersion, loaded,
                            servicesMac(id, "[]", loaded.sequence(), loaded.nextUpdate().toEpochMilli(), true),
                            memberWrites(source, before, loaded, now), now.toEpochMilli(), nextRefresh)
                    : storeSingle(id, configVersion, loaded, now, nextRefresh);
            if (!stored) {
                discarded(source, detail);
                return true;
            }
            if (loaded.listOfLists()) {
                auditMembers(source, before, loaded, now, detail);
            }
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
            auditSigners(source, now);
            return true;
        } finally {
            keeper.cancel(false);
            repository.releaseLease(id, owner);
            sync();
        }
    }

    private boolean storeSingle(final String id, final long configVersion, final LoadedList loaded, final Instant now,
                                final long nextRefresh) {
        final String json = ServicesCodec.encode(loaded.services());
        return repository.recordSuccess(id, owner, configVersion, loaded, json,
                servicesMac(id, json, loaded.sequence(), loaded.nextUpdate().toEpochMilli(), false), now.toEpochMilli(),
                nextRefresh);
    }

    private List<TrustedListRepository.MemberWrite> memberWrites(final TrustedListSource source,
            final List<TrustedListSource.Member> before, final LoadedList loaded, final Instant now) {
        final List<TrustedListRepository.MemberWrite> out = new ArrayList<>();
        for (final LoadedList.Member m : loaded.members()) {
            if (m.loaded()) {
                final String json = ServicesCodec.encode(m.services());
                out.add(new TrustedListRepository.MemberWrite(m, json, memberMac(source.id(), m.key(), json,
                        m.sequence(), m.nextUpdate().toEpochMilli()), null));
            } else {
                final TrustedListSource.Member old = before.stream().filter(b -> b.key().equals(m.key())).findFirst()
                        .orElse(null);
                final Instant lastGood = old == null || old.servicesJson() == null || old.nextUpdate() == null ? null
                        : Instant.ofEpochMilli(old.nextUpdate());
                final TrustedListHealth.Status status = TrustedListHealth.evaluate(true, lastGood,
                        Duration.ofHours(source.config().graceHours()), true, true, now);
                out.add(new TrustedListRepository.MemberWrite(m, null, null, status.name()));
            }
        }
        return out;
    }

    /** One audit event (and a log line) per member that failed; the source's own event lists them all. */
    private void auditMembers(final TrustedListSource source, final List<TrustedListSource.Member> before,
                              final LoadedList loaded, final Instant now, final Map<String, String> sourceDetail) {
        final List<String> ok = new ArrayList<>();
        final List<String> failedMembers = new ArrayList<>();
        for (final LoadedList.Member m : loaded.members()) {
            final String label = m.territory() == null ? m.location() : m.territory();
            if (m.loaded()) {
                ok.add(label);
                continue;
            }
            failedMembers.add(label);
            final Map<String, String> detail = detail(source);
            detail.put("territory", m.territory() == null ? "" : m.territory());
            detail.put("memberUrl", m.location());
            detail.put("reason", m.errorKind().name());
            detail.put("message", m.errorMessage());
            final TrustedListSource.Member old = before.stream().filter(b -> b.key().equals(m.key())).findFirst()
                    .orElse(null);
            if (old != null && old.servicesJson() != null && old.nextUpdate() != null) {
                final Instant until = Instant.ofEpochMilli(old.nextUpdate())
                        .plus(Duration.ofHours(source.config().graceHours()));
                if (now.isBefore(until)) {
                    detail.put("anchorsKeptUntil", until.toString());
                }
            }
            LOG.warn("trusted lists: member {} ({}) of {} of realm {} refused ({}: {}){}",
                    LogSafe.sanitize(label), LogSafe.sanitize(m.location()), LogSafe.sanitize(source.config().name()),
                    LogSafe.sanitize(source.realmId()), m.errorKind(), LogSafe.sanitize(m.errorMessage()),
                    detail.containsKey("anchorsKeptUntil") ? "; its last good anchors are kept until "
                            + detail.get("anchorsKeptUntil") : "; it gives no anchors");
            audit.emit(source.realmId(), MEMBER_REFRESH_FAILED, source.id(), "FAILURE", detail);
        }
        sourceDetail.put("membersLoaded", String.join(" ", ok));
        sourceDetail.put("membersFailed", String.join(" ", failedMembers));
    }

    /** Audits every pinned signer that has expired or expires within {@link #SIGNER_WARNING}: re-pin in time. */
    private void auditSigners(final TrustedListSource source, final Instant now) {
        final List<X509Certificate> signers;
        try {
            signers = PemCertificates.parse(source.config().signerCertificates());
        } catch (final IllegalArgumentException e) {
            return;
        }
        for (final X509Certificate signer : signers) {
            final Instant notAfter = signer.getNotAfter().toInstant();
            if (notAfter.isAfter(now.plus(SIGNER_WARNING))) {
                continue;
            }
            final boolean expired = !notAfter.isAfter(now);
            final Map<String, String> detail = detail(source);
            detail.put("signerSubject", signer.getSubjectX500Principal().getName());
            detail.put("signerNotAfter", notAfter.toString());
            LOG.warn("trusted lists: a pinned signer of {} of realm {} {} {}; pin the publisher's new certificate",
                    LogSafe.sanitize(source.config().name()), LogSafe.sanitize(source.realmId()),
                    expired ? "expired on" : "expires on", notAfter);
            audit.emit(source.realmId(), expired ? SIGNER_EXPIRED : SIGNER_EXPIRING, source.id(), "FAILURE", detail);
        }
    }

    /** The result was not stored: the lease was lost or the settings changed while the list was loading. */
    private void discarded(final TrustedListSource source, final Map<String, String> detail) {
        detail.put("reason", "DISCARDED");
        detail.put("message", "the settings changed or the lease was lost while the list was loading; the result "
                + "was not stored");
        LOG.warn("trusted lists: refresh of {} of realm {} discarded: the settings changed or the lease was lost "
                + "while it ran", LogSafe.sanitize(source.config().name()), LogSafe.sanitize(source.realmId()));
        audit.emit(source.realmId(), DISCARDED, source.id(), "FAILURE", detail);
    }

    private void failed(final TrustedListSource source, final long configVersion, final Instant now, final String kind,
                        final String message, final Map<String, String> detail) {
        final boolean hadGood = source.state().servicesJson() != null && source.state().nextUpdate() != null;
        final TrustedListHealth.Status status = TrustedListHealth.evaluate(source.config().enabled(),
                hadGood ? Instant.ofEpochMilli(source.state().nextUpdate()) : null,
                Duration.ofHours(source.config().graceHours()), true, true, now);
        if (!repository.recordFailure(source.id(), owner, configVersion, status.name(), kind + ": " + message,
                now.toEpochMilli(), now.plus(settings.retryInterval()).toEpochMilli())) {
            discarded(source, detail);
            return;
        }
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

    private TrustedListSpec spec(final TrustedListSource source) {
        final TrustedListSource.Config c = source.config();
        final List<X509Certificate> signers;
        try {
            signers = PemCertificates.parse(c.signerCertificates());
        } catch (final IllegalArgumentException e) {
            throw new IllegalStateException("stored signer certificates cannot be read");
        }
        final boolean hadGood = source.state().servicesJson() != null;
        final Map<String, Long> memberSequences = new java.util.HashMap<>();
        for (final TrustedListSource.Member m : members(source)) {
            if (m.servicesJson() != null && m.sequenceNumber() != null) {
                memberSequences.put(m.key(), m.sequenceNumber());
            }
        }
        return new TrustedListSpec(c.url(), c.format(), signers, Set.copyOf(c.serviceTypes()),
                Set.copyOf(c.acceptedStatuses()), Set.copyOf(c.territories()),
                hadGood ? source.state().sequenceNumber() : null, memberSequences);
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
