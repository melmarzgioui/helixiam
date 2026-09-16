package group.mfnr.authorization.federation.ldap;

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
 */
public class JndiLdapDirectory implements LdapDirectory {

    private static final Logger LOG = LogManager.getLogger(JndiLdapDirectory.class);

    @Override
    public Optional<Map<String, String>> authenticate(final LdapProviderConfig config,
                                                       final String username, final String password) {
        DirContext serviceCtx = null;
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
        }
    }

    private static Hashtable<String, String> env(final String url, final String principal, final String credentials) {
        final Hashtable<String, String> env = new Hashtable<>();
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.PROVIDER_URL, url);
        env.put(Context.SECURITY_AUTHENTICATION, "simple");
        env.put(Context.SECURITY_PRINCIPAL, principal);
        env.put(Context.SECURITY_CREDENTIALS, credentials);
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
