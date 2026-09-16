/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.ldap;

import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;
import com.unboundid.ldap.listener.InMemoryListenerConfig;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Helix IAM E5: live validation of {@link JndiLdapDirectory} against a real, embedded in-memory LDAP
 * server (UnboundID). Exercises the actual JNDI bind + search path — not a mock — so the directory
 * federation is proven end-to-end, fully offline.
 */
class JndiLdapDirectoryIntegrationTest {

    private static InMemoryDirectoryServer ldap;
    private static LdapProviderConfig config;

    private final JndiLdapDirectory directory = new JndiLdapDirectory();

    @BeforeAll
    static void startDirectory() throws Exception {
        final InMemoryDirectoryServerConfig cfg = new InMemoryDirectoryServerConfig("dc=corp");
        cfg.addAdditionalBindCredentials("cn=admin,dc=corp", "admin-pw");
        cfg.setListenerConfigs(InMemoryListenerConfig.createLDAPConfig("default", 0));
        ldap = new InMemoryDirectoryServer(cfg);
        ldap.startListening();

        ldap.add("dn: dc=corp", "objectClass: top", "objectClass: domain", "dc: corp");
        ldap.add("dn: ou=people,dc=corp", "objectClass: top", "objectClass: organizationalUnit", "ou: people");
        ldap.add("dn: uid=ada,ou=people,dc=corp",
                "objectClass: top", "objectClass: person", "objectClass: organizationalPerson", "objectClass: inetOrgPerson",
                "uid: ada", "cn: Ada Lovelace", "sn: Lovelace", "givenName: Ada",
                "mail: ada@corp", "userPassword: s3cret");

        final int port = ldap.getListenPort();
        config = new LdapProviderConfig("corp-ad", "Corp AD", "ldap://localhost:" + port,
                "cn=admin,dc=corp", "admin-pw", "ou=people,dc=corp", "(uid={0})",
                "uid", "mail", "givenName", "sn");
    }

    @AfterAll
    static void stopDirectory() {
        if (ldap != null) {
            ldap.shutDown(true);
        }
    }

    @Test
    void bindsAndReturnsAttributesForValidCredentials() {
        final Optional<Map<String, String>> result = directory.authenticate(config, "ada", "s3cret");

        assertThat(result).isPresent();
        final Map<String, String> attrs = result.orElseThrow();
        assertThat(attrs).containsEntry("uid", "ada").containsEntry("mail", "ada@corp")
                .containsEntry("givenName", "Ada").containsEntry("sn", "Lovelace");
    }

    @Test
    void rejectsAWrongPassword() {
        assertThat(directory.authenticate(config, "ada", "wrong")).isEmpty();
    }

    @Test
    void rejectsAnUnknownUser() {
        assertThat(directory.authenticate(config, "ghost", "s3cret")).isEmpty();
    }
}
