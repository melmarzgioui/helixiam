/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.messaging.email;

import io.helixiam.authorization.amqp.messaging.ResolvedProviderDto;
import io.helixiam.authorization.messaging.email.DeliveryResult.Reason;
import io.helixiam.authorization.observability.HelixMetrics;
import io.helixiam.authorization.security.audit.AuditContext;
import io.helixiam.authorization.security.audit.AuditEvent;
import io.helixiam.authorization.security.audit.AuditLog;
import io.helixiam.common.log.LogSafe;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * The single entry point for sending an email: {@link #deliver(String, EmailMessage)}.
 *
 * <p>It picks the provider (the realm's enabled {@code EMAIL} provider with a known driver, else the global default
 * of {@link GlobalEmailProvider}), re-reading it at every call so a changed or rotated secret applies at once, hands
 * the message to the matching {@link EmailTransport}, and returns the classified {@link DeliveryResult}. It never
 * throws. Every attempt is counted in {@code helix_email_send_total{realm,driver,result}}; a provider that refuses
 * the credentials also raises {@code helix_email_provider_auth_failures_total}, a WARN log line and an
 * {@code EMAIL_PROVIDER_AUTH_FAILED} audit event, because only an operator can fix it.
 *
 * <p>A persisted retry queue wraps this method: store the realm and the {@link EmailMessage} (its
 * {@link EmailMessage#messageId()} is stable across attempts), call {@code deliver} for each attempt, and retry only
 * a {@link DeliveryResult#isRetryable() retryable} result.
 */
public class EmailDelivery {

    /** The realm's enabled {@code EMAIL} providers, with their secrets (server-side only). */
    @FunctionalInterface
    public interface ProviderLookup {
        List<ResolvedProviderDto> enabledEmailProviders(String realm);
    }

    private static final Logger LOG = LogManager.getLogger(EmailDelivery.class);

    private final ProviderLookup lookup;
    private final List<? extends EmailTransport> transports;
    private final GlobalEmailProvider global;
    private final HelixMetrics metrics;
    private final AuditLog audit;

    public EmailDelivery(final ProviderLookup lookup, final List<? extends EmailTransport> transports,
                         final GlobalEmailProvider global, final HelixMetrics metrics, final AuditLog audit) {
        this.lookup = lookup;
        this.transports = transports == null ? List.of() : transports;
        this.global = global;
        this.metrics = metrics;
        this.audit = audit;
    }

    /**
     * Sends {@code message} for {@code realm} (null: no realm, global default only) and returns the classified
     * result. {@link Reason#NO_PROVIDER} when neither the realm nor the server has an email provider.
     */
    public DeliveryResult deliver(final String realm, final EmailMessage message) {
        final Optional<ResolvedProviderDto> provider = realmProvider(realm).or(this::globalProvider);
        if (provider.isEmpty()) {
            return DeliveryResult.permanent(Reason.NO_PROVIDER,
                    "No email provider is configured for the realm, nor globally");
        }
        return deliver(realm, provider.get(), message);
    }

    /** The realm's enabled {@code EMAIL} provider whose driver has a transport; empty when there is none. */
    public Optional<ResolvedProviderDto> realmProvider(final String realm) {
        if (realm == null || lookup == null) {
            return Optional.empty();
        }
        final List<ResolvedProviderDto> enabled;
        try {
            enabled = lookup.enabledEmailProviders(realm);
        } catch (final RuntimeException e) {
            LOG.warn("Could not resolve the EMAIL provider of realm {}: {}", LogSafe.sanitize(realm),
                    LogSafe.sanitize(e.getClass().getSimpleName()));
            return Optional.empty();
        }
        if (enabled == null || enabled.isEmpty()) {
            return Optional.empty();
        }
        for (final ResolvedProviderDto p : enabled) {
            if (transport(p.driver()) != null) {
                return Optional.of(p);
            }
        }
        LOG.warn("Realm {} has an EMAIL provider with an unknown driver {}; using the global default",
                LogSafe.sanitize(realm), LogSafe.sanitize(enabled.get(0).driver()));
        return Optional.empty();
    }

    private Optional<ResolvedProviderDto> globalProvider() {
        try {
            return global == null ? Optional.empty() : global.resolve();
        } catch (final RuntimeException e) {
            LOG.warn("Could not build the global email provider: {}", LogSafe.sanitize(e.getClass().getSimpleName()));
            return Optional.empty();
        }
    }

    /** Sends through {@code provider} (already resolved); the same metrics, logs and alerts as above. */
    public DeliveryResult deliver(final String realm, final ResolvedProviderDto provider, final EmailMessage message) {
        final EmailTransport transport = transport(provider.driver());
        final String driver = transport == null ? String.valueOf(provider.driver()) : transport.driver();
        DeliveryResult result;
        if (transport == null) {
            result = DeliveryResult.permanent(Reason.CONFIGURATION, "Unknown email driver");
        } else {
            try {
                result = transport.deliver(provider, message);
                if (result == null) {
                    result = DeliveryResult.transientFailure(Reason.PROVIDER_ERROR, "The email driver returned no result");
                }
            } catch (final RuntimeException e) {
                result = DeliveryResult.transientFailure(Reason.PROVIDER_ERROR,
                        "The email driver failed (" + e.getClass().getSimpleName() + ")");
            }
        }
        result = withoutSecret(result, provider.secret());
        record(realm, driver, message, result);
        return result;
    }

    private void record(final String realm, final String driver, final EmailMessage message,
                        final DeliveryResult result) {
        if (metrics != null) {
            metrics.recordEmailSend(realm, driver, result.status().name());
        }
        if (result.isSuccess()) {
            LOG.info("Email {} of realm {} {} via {}", LogSafe.sanitize(message.messageId()), LogSafe.sanitize(realm),
                    result.status(), LogSafe.sanitize(driver));
        } else {
            LOG.warn("Email {} of realm {} not delivered via {}: {} {} ({})", LogSafe.sanitize(message.messageId()),
                    LogSafe.sanitize(realm), LogSafe.sanitize(driver), result.status(), result.reason(),
                    LogSafe.sanitize(result.diagnostic()));
        }
        if (result.reason() == Reason.AUTHENTICATION) {
            credentialsRefused(realm, driver, result);
        }
    }

    /** The operator-facing signal of a refused credential: metric, WARN log and audit event. */
    private void credentialsRefused(final String realm, final String driver, final DeliveryResult result) {
        if (metrics != null) {
            metrics.recordEmailProviderAuthFailure(realm, driver);
        }
        LOG.warn("ACTION NEEDED: the {} email provider of realm {} refused HelixIAM's credentials ({}). Check the API "
                        + "token or password and, for an API provider, that the sending domain is set up. Email is not "
                        + "being delivered.", LogSafe.sanitize(driver), LogSafe.sanitize(realm == null ? "(global)" : realm),
                LogSafe.sanitize(result.diagnostic()));
        if (audit != null) {
            try {
                final Map<String, String> detail = new LinkedHashMap<>();
                detail.put("driver", driver);
                detail.put("status", result.status().name());
                if (result.diagnostic() != null) {
                    detail.put("diagnostic", result.diagnostic());
                }
                audit.emit(AuditEvent.admin(AuditContext.nowIso(), "EMAIL_PROVIDER_AUTH_FAILED",
                        realm == null ? "(global)" : realm, "system", null, "messaging-provider", "EMAIL/" + driver,
                        "FAILURE", detail));
            } catch (final RuntimeException e) {
                LOG.debug("Audit of the refused email credentials failed", e);
            }
        }
    }

    private EmailTransport transport(final String driver) {
        if (driver == null) {
            return null;
        }
        for (final EmailTransport t : transports) {
            if (t.driver().equalsIgnoreCase(driver.trim())) {
                return t;
            }
        }
        return null;
    }

    /** Defence in depth: whatever a driver put in the diagnostic, the provider's secret never leaves here. */
    private static DeliveryResult withoutSecret(final DeliveryResult r, final String secret) {
        if (r.diagnostic() == null || secret == null || secret.length() < 4 || !r.diagnostic().contains(secret)) {
            return r;
        }
        return new DeliveryResult(r.status(), r.reason(), r.providerMessageId(), r.diagnostic().replace(secret, "***"),
                r.bouncedRecipients());
    }
}
