/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.ldap;

import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;
import com.unboundid.ldap.listener.InMemoryListenerConfig;
import io.helixiam.common.net.LdapEgressGuard;
import io.helixiam.testsupport.TestTls;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Admin-configured LDAP URLs: ldap / ldaps only, through an outbound guard of their own. Internal directories are a
 * real use case, so private addresses are allowed only for hosts or CIDRs the deployment lists in
 * {@code helix.federation.ldap.allowed-hosts}; a realm admin alone cannot reach them. The connection is pinned to the
 * validated address and LDAPS is verified against the configured name.
 */
class LdapEgressTest {

    private InMemoryDirectoryServer ldap;

    @AfterEach
    void stop() {
        if (ldap != null) {
            ldap.shutDown(true);
        }
    }

    private int start(final javax.net.ssl.SSLServerSocketFactory tls) throws Exception {
        final InMemoryDirectoryServerConfig cfg = new InMemoryDirectoryServerConfig("dc=corp");
        cfg.addAdditionalBindCredentials("cn=admin,dc=corp", "admin-pw");
        cfg.setListenerConfigs(tls == null
                ? InMemoryListenerConfig.createLDAPConfig("default", InetAddress.getByAddress(new byte[] {127, 0, 0, 1}),
                        0, null)
                : InMemoryListenerConfig.createLDAPSConfig("ldaps", InetAddress.getByAddress(
                        new byte[] {127, 0, 0, 1}), 0, tls, null));
        ldap = new InMemoryDirectoryServer(cfg);
        ldap.startListening();
        ldap.add("dn: dc=corp", "objectClass: top", "objectClass: domain", "dc: corp");
        ldap.add("dn: ou=people,dc=corp", "objectClass: top", "objectClass: organizationalUnit", "ou: people");
        ldap.add("dn: uid=ada,ou=people,dc=corp", "objectClass: top", "objectClass: person",
                "objectClass: organizationalPerson", "objectClass: inetOrgPerson", "uid: ada", "cn: Ada Lovelace",
                "sn: Lovelace", "givenName: Ada", "mail: ada@corp", "userPassword: s3cret");
        return ldap.getListenPort();
    }

    private static LdapProviderConfig config(final String url) {
        return new LdapProviderConfig("corp", "Corp", url, "cn=admin,dc=corp", "admin-pw", "ou=people,dc=corp",
                "(uid={0})", "uid", "mail", "givenName", "sn");
    }

    /** host answers loopback on the first {@code validated} lookups and the metadata address after them. */
    private static LdapEgressGuard guard(final String allowedHosts, final AtomicInteger lookups, final int validated) {
        return new LdapEgressGuard(allowedHosts, name -> {
            if (name.matches("[0-9.]+")) {
                return new InetAddress[] {InetAddress.getByName(name)};
            }
            final byte[] ip = lookups.getAndIncrement() < validated ? new byte[] {127, 0, 0, 1}
                    : new byte[] {(byte) 169, (byte) 254, (byte) 169, (byte) 254};
            return new InetAddress[] {InetAddress.getByAddress(name, ip)};
        });
    }

    @Test
    void anInternalDirectoryIsRefusedUnlessTheDeploymentListsIt() throws Exception {
        try (ServerSocket counting = new ServerSocket(0, 10, InetAddress.getByAddress(new byte[] {127, 0, 0, 1}))) {
            final AtomicInteger hits = new AtomicInteger();
            final Thread t = new Thread(() -> {
                while (!counting.isClosed()) {
                    try (Socket s = counting.accept()) {
                        hits.incrementAndGet();
                    } catch (final java.io.IOException e) {
                        return;
                    }
                }
            });
            t.setDaemon(true);
            t.start();
            final JndiLdapDirectory directory = new JndiLdapDirectory(guard("", new AtomicInteger(), 99));
            assertThat(directory.authenticate(config("ldap://ldap.internal:" + counting.getLocalPort()), "ada",
                    "s3cret")).isEmpty();
            assertThat(directory.authenticate(config("ldap://127.0.0.1:" + counting.getLocalPort()), "ada",
                    "s3cret")).isEmpty();
            Thread.sleep(200);
            assertThat(hits).hasValue(0);
        }
    }

    @Test
    void aListedHostOrCidrMayBeInternal() throws Exception {
        final int port = start(null);
        assertThat(new JndiLdapDirectory(guard("ldap.internal", new AtomicInteger(), 99))
                .authenticate(config("ldap://ldap.internal:" + port), "ada", "s3cret")).isPresent();
        assertThat(new JndiLdapDirectory(guard("127.0.0.0/8", new AtomicInteger(), 99))
                .authenticate(config("ldap://ldap.other:" + port), "ada", "s3cret")).isPresent();
        assertThat(new JndiLdapDirectory(guard("ldap.internal", new AtomicInteger(), 99))
                .authenticate(config("ldap://ldap.other:" + port), "ada", "s3cret")).isEmpty();
    }

    @Test
    void metadataStaysRefusedEvenWhenItsRangeIsListed() {
        assertThat(new JndiLdapDirectory(guard("169.254.0.0/16", new AtomicInteger(), 0))
                .authenticate(config("ldap://ldap.meta:389"), "ada", "s3cret")).isEmpty();
    }

    @Test
    void onlyLdapAndLdapsUrlsAreUsed() {
        final JndiLdapDirectory directory = new JndiLdapDirectory(guard("127.0.0.0/8", new AtomicInteger(), 99));
        for (final String url : new String[] {"http://127.0.0.1:389", "dns://127.0.0.1", "ldap://a ldap://b",
            "rmi://127.0.0.1:1099/x"}) {
            assertThat(directory.authenticate(config(url), "ada", "s3cret")).as(url).isEmpty();
        }
    }

    @Test
    void bothBindsUseTheOneValidatedAddress() throws Exception {
        final int port = start(null);
        final AtomicInteger lookups = new AtomicInteger();
        assertThat(new JndiLdapDirectory(guard("ldap.rebind.test", lookups, 1))
                .authenticate(config("ldap://ldap.rebind.test:" + port), "ada", "s3cret")).isPresent();
        assertThat(lookups).hasValue(1);
    }

    @Test
    void ldapsIsVerifiedAgainstTheConfiguredNameWhileConnectedToTheValidatedAddress() throws Exception {
        final TestTls tls = TestTls.createFor("ldaps-rebind", "ldap.rebind.test");
        final int port = start(tls.serverContext().getServerSocketFactory());
        final javax.net.ssl.SSLSocketFactory trust = io.helixiam.authorization.messaging.email.TlsTrust
                .context(tls.caPem()).getSocketFactory();
        final AtomicInteger lookups = new AtomicInteger();
        assertThat(new JndiLdapDirectory(guard("ldap.rebind.test", lookups, 1), trust)
                .authenticate(config("ldaps://ldap.rebind.test:" + port), "ada", "s3cret")).isPresent();
        // a certificate for another name is refused
        assertThat(new JndiLdapDirectory(guard("ldap.wrong.test", new AtomicInteger(), 99), trust)
                .authenticate(config("ldaps://ldap.wrong.test:" + port), "ada", "s3cret")).isEmpty();
    }
}
