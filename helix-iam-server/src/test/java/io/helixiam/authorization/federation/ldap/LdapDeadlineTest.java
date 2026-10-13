/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.ldap;

import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;
import com.unboundid.ldap.listener.InMemoryListenerConfig;
import io.helixiam.authorization.security.realm.RealmContextHolder;
import io.helixiam.common.net.FetchLimiter;
import io.helixiam.common.net.LdapEgressGuard;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * An LDAP bind sequence (DNS, service bind, search, user bind) has one total deadline, tries at most two of the
 * addresses a name resolves to, and runs under the LDAP group's per-realm slots, so a directory that hangs cannot
 * hold login threads.
 */
class LdapDeadlineTest {

    private final List<Socket> held = new CopyOnWriteArrayList<>();
    private ServerSocket silent;
    private InMemoryDirectoryServer ldap;

    @AfterEach
    void stop() throws Exception {
        if (silent != null) {
            silent.close();
        }
        for (final Socket s : held) {
            s.close();
        }
        if (ldap != null) {
            ldap.shutDown(true);
        }
        final FetchLimiter.Group g = FetchLimiter.Group.LDAP;
        FetchLimiter.forGroup(g).configure(g.defaultMax(), g.defaultPerRealmMax());
        RealmContextHolder.clear();
    }

    private static LdapProviderConfig config(final String url) {
        return new LdapProviderConfig("corp", "Corp", url, "cn=admin,dc=corp", "admin-pw", "ou=people,dc=corp",
                "(uid={0})", "uid", "mail", "givenName", "sn");
    }

    /** Accepts connections and never answers: every bind waits for a reply. */
    private int silentDirectory(final AtomicInteger accepted) throws Exception {
        silent = new ServerSocket(0, 100, InetAddress.getByAddress(new byte[] {127, 0, 0, 1}));
        final Thread t = new Thread(() -> {
            while (!silent.isClosed()) {
                try {
                    held.add(silent.accept());
                    accepted.incrementAndGet();
                } catch (final Exception e) {
                    return;
                }
            }
        });
        t.setDaemon(true);
        t.start();
        return silent.getLocalPort();
    }

    private int workingDirectory() throws Exception {
        final InMemoryDirectoryServerConfig cfg = new InMemoryDirectoryServerConfig("dc=corp");
        cfg.addAdditionalBindCredentials("cn=admin,dc=corp", "admin-pw");
        cfg.setListenerConfigs(InMemoryListenerConfig.createLDAPConfig("default",
                InetAddress.getByAddress(new byte[] {127, 0, 0, 1}), 0, null));
        ldap = new InMemoryDirectoryServer(cfg);
        ldap.startListening();
        ldap.add("dn: dc=corp", "objectClass: top", "objectClass: domain", "dc: corp");
        ldap.add("dn: ou=people,dc=corp", "objectClass: top", "objectClass: organizationalUnit", "ou: people");
        ldap.add("dn: uid=ada,ou=people,dc=corp", "objectClass: top", "objectClass: person",
                "objectClass: organizationalPerson", "objectClass: inetOrgPerson", "uid: ada", "cn: Ada Lovelace",
                "sn: Lovelace", "givenName: Ada", "mail: ada@corp", "userPassword: s3cret");
        return ldap.getListenPort();
    }

    private static InetAddress[] loopbacks(final String name, final int count) throws java.net.UnknownHostException {
        final InetAddress[] all = new InetAddress[count];
        for (int i = 0; i < count; i++) {
            all[i] = InetAddress.getByAddress(name, new byte[] {127, 0, 0, 1});
        }
        return all;
    }

    @Test
    void aResolverThatHangsDoesNotHoldTheCallerBeyondTheDeadline() {
        final JndiLdapDirectory directory = new JndiLdapDirectory(new LdapEgressGuard("ldap.slow", name -> {
            try {
                Thread.sleep(30_000);
            } catch (final InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            return loopbacks(name, 1);
        }), null, Duration.ofSeconds(1));
        final long start = System.nanoTime();
        assertThat(directory.authenticate(config("ldap://ldap.slow:389"), "ada", "s3cret")).isEmpty();
        assertThat(TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start)).isLessThan(3_000);
    }

    @Test
    void manyAddressesForAHangingDirectoryDoNotHoldTheCallerBeyondTheDeadline() throws Exception {
        final AtomicInteger accepted = new AtomicInteger();
        final int port = silentDirectory(accepted);
        final JndiLdapDirectory directory = new JndiLdapDirectory(new LdapEgressGuard("ldap.many",
                name -> loopbacks(name, 50)), null, Duration.ofSeconds(1));
        final long start = System.nanoTime();
        assertThat(directory.authenticate(config("ldap://ldap.many:" + port), "ada", "s3cret")).isEmpty();
        assertThat(TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start)).isLessThan(3_000);
        Thread.sleep(200);
        assertThat(accepted.get()).isLessThanOrEqualTo(PinnedLdapSocketFactory.MAX_ADDRESSES);
        // the connection held by the hanging bind is closed at the deadline: the server side reads to end of stream
        for (final Socket s : held) {
            s.setSoTimeout(2_000);
            final java.io.InputStream in = s.getInputStream();
            while (in.read() != -1) {
                // drain the bind request
            }
        }
    }

    @Test
    void atMostTwoAddressesAreTried() throws Exception {
        final List<InetAddress> fifty = new ArrayList<>(List.of(loopbacks("x", 50)));
        assertThat(PinnedLdapSocketFactory.MAX_ADDRESSES).isEqualTo(2);
        assertThat(PinnedLdapSocketFactory.toTry(fifty)).hasSize(2);
        assertThat(PinnedLdapSocketFactory.toTry(fifty.subList(0, 1))).hasSize(1);
    }

    @Test
    void aHangingDirectoryInOneRealmDoesNotTakeAnotherRealmsSlots() throws Exception {
        FetchLimiter.forGroup(FetchLimiter.Group.LDAP).configure(8, 1);
        final AtomicInteger accepted = new AtomicInteger();
        final int hanging = silentDirectory(accepted);
        final int working = workingDirectory();
        final JndiLdapDirectory directory = new JndiLdapDirectory(new LdapEgressGuard("127.0.0.0/8",
                name -> loopbacks(name, 1)), null, Duration.ofSeconds(1));
        final JndiLdapDirectory patient = new JndiLdapDirectory(new LdapEgressGuard("127.0.0.0/8",
                name -> loopbacks(name, 1)), null, Duration.ofSeconds(4));

        final CompletableFuture<Optional<java.util.Map<String, String>>> stuck = CompletableFuture.supplyAsync(() -> {
            RealmContextHolder.set("a");
            try {
                return patient.authenticate(config("ldap://ldap.hang:" + hanging), "ada", "s3cret");
            } finally {
                RealmContextHolder.clear();
            }
        });
        while (accepted.get() == 0) {
            Thread.sleep(10);
        }
        // realm a has no slot left: refused at its deadline without connecting
        RealmContextHolder.set("a");
        assertThat(directory.authenticate(config("ldap://ldap.ok:" + working), "ada", "s3cret")).isEmpty();
        // realm b is unaffected
        RealmContextHolder.set("b");
        final long start = System.nanoTime();
        assertThat(directory.authenticate(config("ldap://ldap.ok:" + working), "ada", "s3cret")).isPresent();
        assertThat(TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start)).isLessThan(1_500);
        assertThat(stuck.get(5, TimeUnit.SECONDS)).isEmpty();
    }
}
