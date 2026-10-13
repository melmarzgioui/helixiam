/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.ldap;

import io.helixiam.common.log.LogSafe;
import io.helixiam.common.net.LdapEgressGuard;
import io.helixiam.common.net.SsrfBlockedException;
import io.helixiam.common.net.UnresolvableHostException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;

import javax.net.ssl.SSLSocketFactory;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Hashtable;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

/**
 * Helix IAM E5.2: live {@link LdapDirectory} using JDK JNDI (no extra dependency). It searches for
 * the user with the service-account bind, then binds as the found DN with the supplied password to
 * verify credentials, and returns the requested attributes. Any failure (unknown user / bad password
 * / directory error) yields {@code empty} — the service never throws on an auth miss.
 * {@code @ConditionalOnMissingBean} so a pooled/edge implementation can replace it.
 *
 * <p>The URL is admin-configured, so it goes through an {@link LdapEgressGuard}: only {@code ldap://} and
 * {@code ldaps://}, one host, resolved once; private addresses only for hosts or ranges the deployment lists in
 * {@code helix.federation.ldap.allowed-hosts}. Both binds connect to the validated address through
 * {@link PinnedLdapSocketFactory}; LDAPS verifies the certificate against the configured host name. Referrals are
 * ignored (a referral could point anywhere), connections are not pooled, and reads time out.
 */
public class JndiLdapDirectory implements LdapDirectory {

    private static final Logger LOG = LogManager.getLogger(JndiLdapDirectory.class);

    static final int CONNECT_TIMEOUT_MILLIS = 10_000;
    static final int READ_TIMEOUT_MILLIS = 15_000;

    private final LdapEgressGuard guard;
    private final SSLSocketFactory tls;

    /** Public directories only (no internal host listed). */
    public JndiLdapDirectory() {
        this(new LdapEgressGuard(""));
    }

    public JndiLdapDirectory(final LdapEgressGuard guard) {
        this(guard, null);
    }

    /** {@code tls} null: the JVM default trust. */
    public JndiLdapDirectory(final LdapEgressGuard guard, final SSLSocketFactory tls) {
        this.guard = guard;
        this.tls = tls;
    }

    @Override
    public Optional<Map<String, String>> authenticate(final LdapProviderConfig config,
                                                       final String username, final String password) {
        final PinnedLdapSocketFactory.Target target;
        try {
            target = target(config.url());
        } catch (final UnresolvableHostException e) {
            LOG.info("LDAP provider {}: the directory host could not be resolved", LogSafe.sanitize(config.alias()));
            return Optional.empty();
        } catch (final SsrfBlockedException e) {
            LOG.warn("LDAP provider {}: {}", LogSafe.sanitize(config.alias()), e.getMessage());
            return Optional.empty();
        }
        DirContext serviceCtx = null;
        PinnedLdapSocketFactory.set(target);
        try {
            serviceCtx = new InitialDirContext(env(config.url(), config.bindDn(), config.bindPassword()));

            final SearchControls controls = new SearchControls();
            controls.setSearchScope(SearchControls.SUBTREE_SCOPE);
            controls.setReturningAttributes(new String[]{
                    config.uidAttribute(), config.emailAttribute(),
                    config.firstNameAttribute(), config.lastNameAttribute()});

            final NamingEnumeration<SearchResult> results = serviceCtx.search(
                    config.userSearchBase(), config.userSearchFilter(), new Object[]{username}, controls);
            if (results == null || !results.hasMore()) {
                return Optional.empty();
            }
            final SearchResult result = results.next();
            final String userDn = result.getNameInNamespace();
            final Map<String, String> attributes = toMap(result.getAttributes());

            // Verify the password by binding as the located user DN.
            DirContext userCtx = null;
            try {
                userCtx = new InitialDirContext(env(config.url(), userDn, password));
            } finally {
                close(userCtx);
            }
            return Optional.of(attributes);
        } catch (final Exception e) {
            LOG.info("LDAP authentication failed for user '{}' at {}: {}", username, config.alias(), e.getMessage());
            return Optional.empty();
        } finally {
            close(serviceCtx);
            PinnedLdapSocketFactory.clear();
        }
    }

    /** One {@code ldap://} or {@code ldaps://} URL, its host resolved and checked once. */
    private PinnedLdapSocketFactory.Target target(final String url) throws SsrfBlockedException {
        if (url == null || url.isBlank() || url.trim().chars().anyMatch(Character::isWhitespace)) {
            throw new SsrfBlockedException("The LDAP URL must be a single ldap:// or ldaps:// URL");
        }
        final URI uri;
        try {
            uri = new URI(url.trim());
        } catch (final URISyntaxException e) {
            throw new SsrfBlockedException("The LDAP URL is malformed", e);
        }
        final String scheme = uri.getScheme() == null ? "" : uri.getScheme().toLowerCase(java.util.Locale.ROOT);
        final boolean ldaps = "ldaps".equals(scheme);
        if (!ldaps && !"ldap".equals(scheme)) {
            throw new SsrfBlockedException("The LDAP URL must use ldap:// or ldaps://");
        }
        String host = uri.getHost();
        if (host == null || host.isBlank() || uri.getRawUserInfo() != null) {
            throw new SsrfBlockedException("The LDAP URL has no host");
        }
        if (host.startsWith("[") && host.endsWith("]")) {
            host = host.substring(1, host.length() - 1);
        }
        final int port = uri.getPort() > 0 ? uri.getPort() : ldaps ? 636 : 389;
        final LdapEgressGuard.Target validated = guard.resolve(host, port);
        final SSLSocketFactory socketTls = !ldaps ? null
                : tls != null ? tls : (SSLSocketFactory) SSLSocketFactory.getDefault();
        return new PinnedLdapSocketFactory.Target(validated.addresses(), port, CONNECT_TIMEOUT_MILLIS, socketTls);
    }

    private static Hashtable<String, String> env(final String url, final String principal, final String credentials) {
        final Hashtable<String, String> env = new Hashtable<>();
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.PROVIDER_URL, url);
        env.put(Context.SECURITY_AUTHENTICATION, "simple");
        env.put(Context.SECURITY_PRINCIPAL, principal);
        env.put(Context.SECURITY_CREDENTIALS, credentials);
        // every socket goes to the validated address (no connect.timeout: JNDI then asks for a connected socket)
        env.put("java.naming.ldap.factory.socket", PinnedLdapSocketFactory.class.getName());
        env.put(Context.REFERRAL, "ignore");
        env.put("com.sun.jndi.ldap.connect.pool", "false");
        env.put("com.sun.jndi.ldap.read.timeout", Integer.toString(READ_TIMEOUT_MILLIS));
        return env;
    }

    private static Map<String, String> toMap(final Attributes attributes) throws Exception {
        final Map<String, String> map = new LinkedHashMap<>();
        if (attributes == null) {
            return map;
        }
        final NamingEnumeration<? extends Attribute> all = attributes.getAll();
        while (all.hasMore()) {
            final Attribute attribute = all.next();
            final Object value = attribute.get();
            if (value != null) {
                map.put(attribute.getID(), value.toString());
            }
        }
        return map;
    }

    private static void close(final DirContext ctx) {
        if (ctx != null) {
            try {
                ctx.close();
            } catch (final Exception ignored) {
                // best-effort close
            }
        }
    }
}
