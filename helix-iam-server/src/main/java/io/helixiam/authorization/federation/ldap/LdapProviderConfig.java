/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.ldap;

/**
 * Helix IAM E5.2: configuration for an LDAP/AD directory the realm federates against. Unlike OIDC/
 * SAML2, LDAP is direct-bind (no redirect): the user's credentials are bound against the directory,
 * and on success the directory's attributes become a {@code BrokeredIdentity}.
 *
 * @param alias                stable provider alias (registry key)
 * @param displayName          label for the login page / admin console
 * @param url                  directory URL, e.g. {@code ldaps://ad.corp:636}
 * @param bindDn               service-account DN used to search for the user (before their bind)
 * @param bindPassword         service-account password
 * @param userSearchBase       base DN to search under, e.g. {@code ou=people,dc=corp}
 * @param userSearchFilter     filter with a {@code {0}} placeholder for the username, e.g. {@code (uid={0})}
 * @param uidAttribute         attribute used as the stable external subject (e.g. {@code uid}/{@code objectGUID})
 * @param emailAttribute       attribute holding the email (e.g. {@code mail})
 * @param firstNameAttribute   attribute holding the given name (e.g. {@code givenName})
 * @param lastNameAttribute    attribute holding the surname (e.g. {@code sn})
 */
public record LdapProviderConfig(String alias, String displayName, String url, String bindDn, String bindPassword,
                                 String userSearchBase, String userSearchFilter, String uidAttribute,
                                 String emailAttribute, String firstNameAttribute, String lastNameAttribute) {
}
