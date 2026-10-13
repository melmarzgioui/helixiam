/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet;

import io.helixiam.authorization.domain.federation.FederatedLinkEntity;
import io.helixiam.authorization.domain.gdpr.GdprEraseDto;
import io.helixiam.authorization.domain.gdpr.GdprExportDto;
import io.helixiam.authorization.domain.tenant.TenantUser;
import io.helixiam.authorization.domain.user.UserCredentials;
import io.helixiam.authorization.domain.user.UserRoles;
import io.helixiam.authorization.federation.IdentityProviderRegistry;
import io.helixiam.authorization.federation.spi.BrokeredIdentity;
import io.helixiam.authorization.federation.spi.IdentityProvider;
import io.helixiam.authorization.federation.spi.IdpMetadata;
import io.helixiam.authorization.federation.wallet.testwallet.TestAccessKeys;
import io.helixiam.authorization.federation.wallet.testwallet.TestPki;
import io.helixiam.authorization.federation.wallet.testwallet.TestWallet;
import io.helixiam.authorization.federation.wallet.transaction.InMemoryWalletTransactionStore;
import io.helixiam.authorization.repository.UserCredentialsRepository;
import io.helixiam.authorization.repository.federation.FederatedLinkRepository;
import io.helixiam.authorization.repository.gdpr.GdprUserMutationRepository;
import io.helixiam.authorization.repository.org.OrganizationMemberRepository;
import io.helixiam.authorization.repository.org.OrganizationRepository;
import io.helixiam.authorization.repository.tenant.TenantUserRepository;
import io.helixiam.authorization.security.audit.AuditLog;
import io.helixiam.authorization.service.gdpr.ConsentLedgerService;
import io.helixiam.authorization.service.gdpr.GdprAdminService;
import io.helixiam.authorization.service.user.CredentialAdminService;
import io.helixiam.common.net.OutboundUrlGuard;
import io.helixiam.common.startup.DeploymentProfile;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.SecureRandom;
import java.time.Clock;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Task 26: a wallet link is a {@code federated_link} row whose external subject is the {@link WalletSubject} HMAC — a
 * pseudonymous identifier, not the PID value, but still not something the GDPR export should hand back as if it were
 * an ordinary external account id. {@link GdprAdminService#export} must show only the alias and the provider's display
 * name for a wallet link, never the hash; {@link GdprAdminService#erase} (anonymize) must drop the wallet link rows.
 * Every other federated link (OIDC, SAML, eID) keeps behaving exactly as before.
 *
 * <p>Drives the real {@link IdentityProviderRegistry} with a real {@link WalletIdentityProvider} (built the same way
 * {@code WalletAuditE2eTest} does) alongside a bare-bones non-wallet provider, so the wallet/non-wallet distinction in
 * {@code GdprAdminService} is exercised against production wiring, not a stub.
 */
class WalletGdprE2eTest {

    private static final String REALM = "gov";
    private static final String WALLET_ALIAS = "eudi-wallet";
    private static final String OIDC_ALIAS = "google";
    private static final String USER_ID = "u-1";

    private static final TestPki ACCESS_PKI = TestPki.create("Gdpr Access");
    private static final TestPki.Leaf ACCESS = ACCESS_PKI.issueLeaf(TestPki.LeafSpec.defaults());
    private static final TestWallet WALLET = TestWallet.create();

    private UserCredentialsRepository users;
    private TenantUserRepository tenantUsers;
    private OrganizationRepository organizations;
    private OrganizationMemberRepository orgMembers;
    private FederatedLinkRepository federatedLinks;
    private CredentialAdminService credentials;
    private ConsentLedgerService consents;
    private GdprUserMutationRepository mutation;
    private IdentityProviderRegistry registry;
    private GdprAdminService service;

    @BeforeEach
    void setUp() {
        users = mock(UserCredentialsRepository.class);
        tenantUsers = mock(TenantUserRepository.class);
        organizations = mock(OrganizationRepository.class);
        orgMembers = mock(OrganizationMemberRepository.class);
        federatedLinks = mock(FederatedLinkRepository.class);
        credentials = mock(CredentialAdminService.class);
        consents = mock(ConsentLedgerService.class);
        mutation = mock(GdprUserMutationRepository.class);
        registry = new IdentityProviderRegistry(List.of(walletProvider(), fakeOidcProvider()));
        when(orgMembers.findAllByUserId(any())).thenReturn(List.of());
        when(consents.list(any(), any())).thenReturn(List.of());
        service = new GdprAdminService(users, tenantUsers, organizations, orgMembers, federatedLinks, credentials,
                consents, mutation, registry);
    }

    @Test
    void export_walletLink_carriesAliasAndDisplayName_neverTheSubjectHash() {
        final String hash = hex();
        seedUserAndRealmLink();
        when(federatedLinks.findAllByUserId(USER_ID)).thenReturn(List.of(
                new FederatedLinkEntity(WALLET_ALIAS, hash, USER_ID),
                new FederatedLinkEntity(OIDC_ALIAS, "ext-123", USER_ID)));

        final GdprExportDto export = service.export(REALM, USER_ID);

        final GdprExportDto.GdprFederatedLink wallet = export.federatedLinks().stream()
                .filter(f -> f.idpAlias().equals(WALLET_ALIAS)).findFirst().orElseThrow();
        assertThat(wallet.externalSubject()).isNull();
        assertThat(wallet.displayName()).isEqualTo("Wallet");

        final GdprExportDto.GdprFederatedLink oidc = export.federatedLinks().stream()
                .filter(f -> f.idpAlias().equals(OIDC_ALIAS)).findFirst().orElseThrow();
        assertThat(oidc.externalSubject()).isEqualTo("ext-123");

        assertThat(export.toString()).doesNotContain(hash);
    }

    @Test
    void erase_anonymize_removesTheWalletLink_butLeavesOtherFederatedLinksAlone() {
        final String hash = hex();
        seedUserAndRealmLink();
        when(credentials.list(USER_ID)).thenReturn(List.of());
        final FederatedLinkEntity walletLink = new FederatedLinkEntity(WALLET_ALIAS, hash, USER_ID);
        final FederatedLinkEntity oidcLink = new FederatedLinkEntity(OIDC_ALIAS, "ext-123", USER_ID);
        when(federatedLinks.findAllByUserId(USER_ID)).thenReturn(List.of(walletLink, oidcLink));

        service.erase(new GdprEraseDto(REALM, USER_ID, "anonymize"));

        verify(federatedLinks).delete(walletLink);
        verify(federatedLinks, never()).delete(oidcLink);
    }

    @Test
    void erase_hardDelete_reliesOnTheForeignKeyCascade_notAnExplicitWalletUnlink() {
        seedUserAndRealmLink();

        service.erase(new GdprEraseDto(REALM, USER_ID, "hard"));

        // federated_link has ON DELETE CASCADE to user_credentials (see GdprAdminService javadoc): the single
        // users.delete(user) below already removes every federated_link row, wallet or not. No separate lookup.
        verify(users).delete(any());
        verify(federatedLinks, never()).findAllByUserId(any());
        verify(federatedLinks, never()).delete(any());
    }

    private void seedUserAndRealmLink() {
        final UserCredentials user = new UserCredentials();
        user.setUserId(USER_ID);
        user.setUsername("alice");
        user.setEmail("alice@example.com");
        final TenantUser link = new TenantUser();
        link.setTenantId(REALM);
        link.setUserId(USER_ID);
        link.getRoles().add(new UserRoles("auditor", REALM));
        when(tenantUsers.findByTenantIdAndUserId(REALM, USER_ID)).thenReturn(Optional.of(link));
        when(users.findByUserId(USER_ID)).thenReturn(Optional.of(user));
        when(tenantUsers.findAllByUserId(USER_ID)).thenReturn(List.of(link));
        when(credentials.list(USER_ID)).thenReturn(List.of());
    }

    private static IdentityProvider walletProvider() {
        final TestAccessKeys keys = new TestAccessKeys(ACCESS, "eudi-access", REALM);
        final InMemoryWalletTransactionStore store = new InMemoryWalletTransactionStore(Clock.systemUTC(), 100, null);
        final Map<String, String> config = new HashMap<>();
        config.put("accessKeyRef", keys.ref(REALM));
        config.put("trustAnchors", WALLET.pki().rootPem());
        config.put("revocationChecking", "OFF");
        config.put("credentialFormats", "[\"dc+sd-jwt\"]");
        return new WalletIdentityProviders(new WalletConfigValidator(keys, DeploymentProfile.production()), keys,
                store, new OutboundUrlGuard(), mock(AuditLog.class))
                .build(REALM, WalletProviderConfig.fromStored(WALLET_ALIAS, "Wallet", config));
    }

    /** A bare-bones non-wallet provider: only {@code metadata()} is exercised by this test. */
    private static IdentityProvider fakeOidcProvider() {
        return new IdentityProvider() {
            @Override
            public IdpMetadata metadata() {
                return IdpMetadata.of(OIDC_ALIAS, IdpMetadata.Protocol.OIDC, "Google");
            }

            @Override
            public RedirectResponse start(final AuthnRequestContext context) {
                throw new UnsupportedOperationException();
            }

            @Override
            public BrokeredIdentity callback(final CallbackContext context) {
                throw new UnsupportedOperationException();
            }

            @Override
            public void logout(final LogoutContext context) {
                throw new UnsupportedOperationException();
            }
        };
    }

    private static String hex() {
        final byte[] bytes = new byte[32];
        new SecureRandom().nextBytes(bytes);
        return HexFormat.of().formatHex(bytes);
    }
}
