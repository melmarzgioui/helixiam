/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.security.scim;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Helix IAM B7: outbound SCIM provisioning. {@link ScimProvisioningClient} builds the SCIM 2.0 User
 * resource (RFC 7643) pushed to a downstream service provider and the {@code externalId} filter used to
 * locate an already-provisioned resource for update/delete. Pure + unit-testable; the HTTP egress lives
 * in the dispatcher.
 */
class ScimProvisioningClientTest {

    private ScimUserView view() {
        return new ScimUserView("u-1", "ada", "ada@x.io", true, "Ada", "Lovelace");
    }

    @Test
    void buildsACoreScimUserResourceWithExternalIdAndActiveFlag() {
        final Map<String, Object> r = ScimProvisioningClient.userResource(view());

        assertThat(r.get("schemas")).isEqualTo(List.of("urn:ietf:params:scim:schemas:core:2.0:User"));
        assertThat(r.get("userName")).isEqualTo("ada");
        assertThat(r.get("externalId")).isEqualTo("u-1"); // the Helix userId — our stable linking key
        assertThat(r.get("active")).isEqualTo(true);
    }

    @Test
    void includesNameAndPrimaryEmailWhenPresent() {
        final Map<String, Object> r = ScimProvisioningClient.userResource(view());

        @SuppressWarnings("unchecked")
        final Map<String, Object> name = (Map<String, Object>) r.get("name");
        assertThat(name).containsEntry("givenName", "Ada").containsEntry("familyName", "Lovelace");

        @SuppressWarnings("unchecked")
        final List<Map<String, Object>> emails = (List<Map<String, Object>>) r.get("emails");
        assertThat(emails).hasSize(1);
        assertThat(emails.get(0)).containsEntry("value", "ada@x.io").containsEntry("primary", true);
    }

    @Test
    void omitsNameAndEmailsWhenAbsent() {
        final Map<String, Object> r = ScimProvisioningClient.userResource(
                new ScimUserView("u-2", "bob", null, false, null, null));

        assertThat(r).doesNotContainKey("name");
        assertThat(r).doesNotContainKey("emails");
        assertThat(r.get("active")).isEqualTo(false);
        assertThat(r.get("userName")).isEqualTo("bob");
    }

    @Test
    void buildsTheUsersCollectionUrlTrimmingTrailingSlash() {
        assertThat(ScimProvisioningClient.usersUrl("https://sp.example/scim/v2/")).isEqualTo("https://sp.example/scim/v2/Users");
        assertThat(ScimProvisioningClient.usersUrl("https://sp.example/scim/v2")).isEqualTo("https://sp.example/scim/v2/Users");
    }

    @Test
    void buildsAnExternalIdFilterUrlToLocateAnExistingResource() {
        final String url = ScimProvisioningClient.externalIdFilterUrl("https://sp.example/scim/v2", "u-1");

        // externalId eq "u-1", URL-encoded.
        assertThat(url).isEqualTo("https://sp.example/scim/v2/Users?filter=externalId%20eq%20%22u-1%22");
    }
}
