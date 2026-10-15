/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet;

import io.helixiam.authorization.federation.spi.BrokeredIdentity;
import io.helixiam.authorization.federation.wallet.dcql.DcqlQueryBuilder;
import io.helixiam.authorization.federation.wallet.dcql.PidQuerySpec;
import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.stream.Collectors;

import static io.helixiam.testsupport.Jackson2Fixtures.assertWritesSame;
import static io.helixiam.testsupport.Jackson2Fixtures.read;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * Jackson 3 upgrade: an EUDI wallet transaction in flight at the upgrade (PostgreSQL {@code wallet_transaction} or the
 * Redis hash) holds JSON written by the Jackson 2 line: the verified identity of every record kind and the DCQL
 * query. The stored wallet connection ({@code identity_provider.config_json}) holds Jackson 2 JSON lists. The current
 * code must read them and write the same bytes (fixtures under {@code upgrade/jackson2/wallet-*}).
 */
class WalletStoredJsonUpgradeTest {

    private static final String ALIAS = "eudi";
    private static final Map<String, String> ATTRIBUTES = attributes();

    private static Map<String, String> attributes() {
        final Map<String, String> a = new LinkedHashMap<>();
        a.put("given_name", "Zoë");
        a.put("family_name", "O'Brien-Ünal");
        a.put("birthdate", "1980-02-29");
        a.put("address", "Straße 1 / 2 <b>&amp;</b>   \"q\" \\ tab\t");
        a.put("emoji", "😀");
        return a;
    }

    private static BrokeredIdentity identity() {
        return new BrokeredIdentity(ALIAS, "subj-0123456789abcdef", "zoe@example.eu", true, ATTRIBUTES,
                "http://eidas.europa.eu/LoA/high");
    }

    @Test
    void anExistingAccountLoginWithAPendingLink_isReadAndWrittenAsBefore() {
        final WalletLinkService.Decision decision = new WalletLinkService.Decision.Existing("user-1",
                new WalletLinkService.PendingLink("realm-a", ALIAS, "hmac-subject", "user-1"));
        assertWritesSame("wallet-login-existing.json",
                VerifiedIdentityJson.write(identity(), decision, "dc+sd-jwt", "CN=PID Issuer, O=Example/Org, C=NL"));

        final VerifiedIdentityJson.StoredLogin stored =
                VerifiedIdentityJson.readLogin(ALIAS, read("wallet-login-existing.json"));
        assertThat(stored.identity()).isEqualTo(identity());
        assertThat(stored.decision()).isEqualTo(decision);
        assertThat(stored.format()).isEqualTo("dc+sd-jwt");
        assertThat(stored.issuerDn()).isEqualTo("CN=PID Issuer, O=Example/Org, C=NL");
    }

    @Test
    void aProvisioningLogin_isReadAndWrittenAsBefore() {
        assertWritesSame("wallet-login-provision.json",
                VerifiedIdentityJson.write(identity(), new WalletLinkService.Decision.Provision(), "mso_mdoc", null));

        final VerifiedIdentityJson.StoredLogin stored =
                VerifiedIdentityJson.readLogin(ALIAS, read("wallet-login-provision.json"));
        assertThat(stored.identity()).isEqualTo(identity());
        assertThat(stored.decision()).isEqualTo(new WalletLinkService.Decision.Provision());
        assertThat(stored.format()).isEqualTo("mso_mdoc");
        assertThat(stored.issuerDn()).isNull();
        // The identity-only form (no decision) as well.
        assertWritesSame("wallet-identity.json", VerifiedIdentityJson.write(identity()));
        assertThat(VerifiedIdentityJson.read(ALIAS, read("wallet-identity.json"))).isEqualTo(identity());
    }

    @Test
    void aRefusedLogin_isReadAndWrittenAsBefore() {
        final WalletLinkService.Decision refused =
                new WalletLinkService.Decision.Refused(WalletSubject.Reason.LINK_REQUIRED);
        assertWritesSame("wallet-login-refused.json",
                VerifiedIdentityJson.write(null, refused, "dc+sd-jwt", "CN=Issuer"));

        final VerifiedIdentityJson.StoredLogin stored =
                VerifiedIdentityJson.readLogin(ALIAS, read("wallet-login-refused.json"));
        assertThat(stored.identity()).isNull();
        assertThat(stored.decision()).isEqualTo(refused);
    }

    @Test
    void linkRecords_areReadAndWrittenAsBefore() {
        final WalletSubject number = new WalletSubject.AdminNumber("a1b2c3", "d4e5f6");
        final WalletSubject tuple = new WalletSubject.Tuple("0f0f0f");
        final WalletSubject unavailable = new WalletSubject.Unavailable(WalletSubject.Reason.WEAK_SUBJECT_NOT_ACKNOWLEDGED);
        assertWritesSame("wallet-link-number.json", VerifiedIdentityJson.writeLink(number));
        assertWritesSame("wallet-link-tuple.json", VerifiedIdentityJson.writeLink(tuple));
        assertWritesSame("wallet-link-unavailable.json", VerifiedIdentityJson.writeLink(unavailable));

        assertThat(VerifiedIdentityJson.readLink(read("wallet-link-number.json"))).isEqualTo(number);
        assertThat(VerifiedIdentityJson.readLink(read("wallet-link-tuple.json"))).isEqualTo(tuple);
        assertThat(VerifiedIdentityJson.readLink(read("wallet-link-unavailable.json"))).isEqualTo(unavailable);
    }

    @Test
    void aVerifyRecord_isReadAndWrittenAsBefore() {
        final Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("age_over_18", true);
        claims.put("nationality", "NL");
        claims.put("given_name", "Zoë / \"Z\"");
        claims.put("resident", false);
        assertWritesSame("wallet-verify.json", VerifiedIdentityJson.writeVerify(
                new WalletSubject.AdminNumber("n-1", null), claims, "http://eidas.europa.eu/LoA/substantial",
                "dc+sd-jwt", "CN=Issuer"));

        final VerifiedIdentityJson.Verification v = VerifiedIdentityJson.readVerify(read("wallet-verify.json"));
        assertThat(v.numberSubject()).isEqualTo("n-1");
        assertThat(v.tupleSubject()).isNull();
        assertThat(v.claims()).containsExactlyEntriesOf(claims);
        assertThat(v.levelOfAssurance()).isEqualTo("http://eidas.europa.eu/LoA/substantial");
        assertThat(v.format()).isEqualTo("dc+sd-jwt");
        assertThat(v.issuerDn()).isEqualTo("CN=Issuer");
    }

    @Test
    void theStoredDcqlQuery_isReadAndWrittenAsBefore() throws Exception {
        final var query = new DcqlQueryBuilder().pidQuery(
                new PidQuerySpec(List.of("urn:eudi:pid:1"), PidQuerySpec.DEFAULT_MDOC_DOCTYPE,
                        List.of("given_name", "family_name", "birthdate", "nationalities", "address.locality")),
                List.of(DcqlQueryBuilder.SD_JWT_FORMAT, DcqlQueryBuilder.MDOC_FORMAT),
                List.of("s9tIpPmhxdiuNkHMEWNpYim8S8Y", "AbC-_0"));
        assertWritesSame("wallet-dcql-query.json", StrictJson.MAPPER.writeValueAsString(query));

        // WalletResponseHandler reads it back strictly; it must be the same tree.
        assertThat(StrictJson.MAPPER.readTree(read("wallet-dcql-query.json"))).isEqualTo(query);
    }

    @Test
    void aStoredWalletConnection_isReadAndWrittenAsBefore() {
        // identity_provider.config_json of a wallet connection: a flat map whose list settings are JSON arrays.
        final Map<String, String> stored = new LinkedHashMap<>();
        stored.put("alias", ALIAS);
        stored.put("displayName", "EUDI Wallet");
        stored.put("clientIdScheme", "x509_hash");
        stored.put("credentialFormats", "[\"dc+sd-jwt\",\"mso_mdoc\"]");
        stored.put("pid.sdJwtVcts", "[\"urn:eudi:pid:1\",\"https://example.eu/pid/1\"]");
        stored.put("pid.requestedClaims", "[\"given_name\",\"family_name\",\"birthdate\"]");
        stored.put("statusList.allowedHosts", "[\"status.example.eu\"]");
        stored.put("dcApi.enabled", "true");
        stored.put("dcApi.expectedOrigins", "[\"https://rp.example.eu\",\"https://app.example.eu:8443\"]");
        stored.put("trustedLists.sources", "[\"tl-1\"]");
        stored.put("trustedLists.serviceTypes", "[\"http://uri.etsi.org/TrstSvc/Svctype/EAA/Pub-EAA\"]");

        final WalletProviderConfig config = WalletProviderConfig.fromStored(stored);
        assertThat(config.credentialFormats()).containsExactly("dc+sd-jwt", "mso_mdoc");
        assertThat(config.pid().sdJwtVcts()).containsExactly("urn:eudi:pid:1", "https://example.eu/pid/1");
        assertThat(config.dcApi().expectedOrigins())
                .containsExactly("https://rp.example.eu", "https://app.example.eu:8443");

        assertWritesSame("wallet-provider-config-stored.txt", new TreeMap<>(config.toStored()).entrySet().stream()
                .map(e -> e.getKey() + "=" + e.getValue()).collect(Collectors.joining("\n", "", "\n")));
    }
}
