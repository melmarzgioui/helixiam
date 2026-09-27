/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.service.client;

import io.helixiam.authorization.domain.ServiceProviderOAuthClient;
import io.helixiam.authorization.repository.ServiceProviderRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/** C5: the bootstrap service account is opt-in, create-only, and needs an acceptable secret. */
class BootstrapServiceAccountServiceTest {

    private static final String GOOD = "g".repeat(40);

    private final ServiceProviderRepository clients = mock(ServiceProviderRepository.class);
    private final ClientRoleAdminService roles = mock(ClientRoleAdminService.class);

    @Test
    void withoutAClientId_nothingHappens() {
        assertThat(service("", GOOD, "").ensureBootstrapServiceAccount())
                .isEqualTo(BootstrapServiceAccountService.Result.NOT_CONFIGURED);
        verify(clients, never()).save(any());
    }

    @Test
    void aShortOrMissingSecret_createsNothing() {
        when(clients.findByClientIdAndRealmIdAndDeleted("prov", "master", false)).thenReturn(Optional.empty());
        assertThat(service("prov", "short", "").ensureBootstrapServiceAccount())
                .isEqualTo(BootstrapServiceAccountService.Result.INVALID_SECRET);
        assertThat(service("prov", "", "/does/not/exist").ensureBootstrapServiceAccount())
                .isEqualTo(BootstrapServiceAccountService.Result.INVALID_SECRET);
        verify(clients, never()).save(any());
    }

    @Test
    void createsOnce_withTheAdminRole() {
        when(clients.findByClientIdAndRealmIdAndDeleted("prov", "master", false)).thenReturn(Optional.empty());
        assertThat(service("prov", GOOD, "").ensureBootstrapServiceAccount())
                .isEqualTo(BootstrapServiceAccountService.Result.CREATED);
        verify(clients).save(any(ServiceProviderOAuthClient.class));
        verify(roles).assignServiceAccountRole(any());

        when(clients.findByClientIdAndRealmIdAndDeleted("prov", "master", false))
                .thenReturn(Optional.of(new ServiceProviderOAuthClient()));
        assertThat(service("prov", GOOD, "").ensureBootstrapServiceAccount())
                .isEqualTo(BootstrapServiceAccountService.Result.EXISTS);
    }

    @Test
    void theSecretFileWins_andItsTrailingNewlineIsIgnored(@TempDir final Path dir) throws Exception {
        final Path file = dir.resolve("secret");
        Files.writeString(file, "f".repeat(40) + "\n");
        assertThat(service("prov", GOOD, file.toString()).resolveSecret()).isEqualTo("f".repeat(40));
        assertThat(service("prov", GOOD + "  ", "").resolveSecret()).isEqualTo(GOOD);
    }

    private BootstrapServiceAccountService service(final String id, final String secret, final String file) {
        return new BootstrapServiceAccountService(clients, roles, id, secret, file);
    }
}
