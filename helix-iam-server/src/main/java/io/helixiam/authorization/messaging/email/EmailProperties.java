/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.messaging.email;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

/**
 * The global (server-wide) email default, used when the realm in context has no enabled {@code EMAIL} provider, or
 * when there is no realm (prefix {@code helix.notification.email}).
 * <ul>
 *   <li>{@code driver}: {@code smtp} (default; {@code helix.notification.smtp.*}), {@code cloudflare}
 *       ({@code helix.notification.cloudflare.*}) or {@code log};</li>
 *   <li>{@code from-address} / {@code from-name}: the sender; default {@code helix.notification.smtp.from-address} /
 *       {@code from-name}.</li>
 *   <li>{@code retry.*}: the persisted retry queue for transient failures ({@link Retry});</li>
 *   <li>{@code rate-limit.*}: the send rate caps ({@link RateLimit}).</li>
 * </ul>
 */
@ConfigurationProperties(prefix = "helix.notification.email")
public class EmailProperties {

    private String driver = "smtp";
    private String fromAddress;
    private String fromName;
    private final Retry retry = new Retry();
    private final RateLimit rateLimit = new RateLimit();

    public Retry getRetry() {
        return retry;
    }

    public RateLimit getRateLimit() {
        return rateLimit;
    }

    public String getDriver() {
        return driver;
    }

    public void setDriver(final String driver) {
        this.driver = driver;
    }

    public String getFromAddress() {
        return fromAddress;
    }

    public void setFromAddress(final String fromAddress) {
        this.fromAddress = fromAddress;
    }

    public String getFromName() {
        return fromName;
    }

    public void setFromName(final String fromName) {
        this.fromName = fromName;
    }

    /**
     * The retry queue ({@code helix.notification.email.retry.*}). A delivery that fails with {@code TRANSIENT_FAILURE}
     * is stored and sent again after each of {@code delays} in turn (each with up to {@code jitter} random spread),
     * never later than {@code max-age} after the first attempt and never after the code in the email expires.
     */
    public static class Retry {

        /** Whether transient failures are retried at all (and the retry worker runs). */
        private boolean enabled = true;
        /** The wait before each retry: 4 retries by default, then the email is given up. */
        private List<Duration> delays = new ArrayList<>(List.of(Duration.ofSeconds(30), Duration.ofMinutes(2),
                Duration.ofMinutes(10), Duration.ofMinutes(30)));
        /** No retry is sent later than this after the first attempt. */
        private Duration maxAge = Duration.ofHours(1);
        /** Random spread of each delay, as a fraction (0.2 = plus or minus 20 percent). */
        private double jitter = 0.2;
        /** How often each replica looks for due retries. */
        private Duration pollInterval = Duration.ofSeconds(5);
        /** At most this many retries are claimed per poll. */
        private int batchSize = 20;
        /** A claimed retry that is not finished within this time (the replica died) is claimed again. */
        private Duration lease = Duration.ofMinutes(2);

        public boolean isEnabled() {
            return enabled;
        }

        public void setEnabled(final boolean enabled) {
            this.enabled = enabled;
        }

        public List<Duration> getDelays() {
            return delays;
        }

        public void setDelays(final List<Duration> delays) {
            this.delays = delays == null ? new ArrayList<>() : new ArrayList<>(delays);
        }

        public Duration getMaxAge() {
            return maxAge;
        }

        public void setMaxAge(final Duration maxAge) {
            this.maxAge = maxAge;
        }

        public double getJitter() {
            return jitter;
        }

        public void setJitter(final double jitter) {
            this.jitter = jitter;
        }

        public Duration getPollInterval() {
            return pollInterval;
        }

        public void setPollInterval(final Duration pollInterval) {
            this.pollInterval = pollInterval;
        }

        public int getBatchSize() {
            return batchSize;
        }

        public void setBatchSize(final int batchSize) {
            this.batchSize = batchSize;
        }

        public Duration getLease() {
            return lease;
        }

        public void setLease(final Duration lease) {
            this.lease = lease;
        }
    }

    /**
     * The send rate caps ({@code helix.notification.email.rate-limit.*}), counted per replica over a sliding minute
     * (a token bucket). {@code 0} switches a cap off. A realm can set its own cap with the {@code sendLimitPerMinute}
     * setting of its {@code EMAIL} provider.
     */
    public static class RateLimit {

        /** Emails per minute per realm (default for realms without their own {@code sendLimitPerMinute}). */
        private int realmPerMinute = 120;
        /** Emails per minute for the whole server (all realms together). */
        private int globalPerMinute = 600;

        public int getRealmPerMinute() {
            return realmPerMinute;
        }

        public void setRealmPerMinute(final int realmPerMinute) {
            this.realmPerMinute = realmPerMinute;
        }

        public int getGlobalPerMinute() {
            return globalPerMinute;
        }

        public void setGlobalPerMinute(final int globalPerMinute) {
            this.globalPerMinute = globalPerMinute;
        }
    }
}
