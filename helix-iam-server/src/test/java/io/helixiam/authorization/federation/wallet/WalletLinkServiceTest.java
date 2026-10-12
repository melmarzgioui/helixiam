/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet;

import io.helixiam.authorization.federation.AccountLinkingPolicy;
import io.helixiam.authorization.federation.wallet.dcql.MatchedPresentations;
import io.helixiam.e2e.AbstractE2eTest;
import io.helixiam.e2e.E2eSeed;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Task 21a: {@link WalletLinkService} on the existing federated-link table, plus the account decision a wallet login
 * makes from a {@link WalletSubject} ("administrative number, else link"). Real resolver, real pepper, real database.
 */
class WalletLinkServiceTest extends AbstractE2eTest {

    private static final WalletProviderConfig.Subject NUMBER_ELSE_LINK =
            new WalletProviderConfig.Subject(WalletProviderConfig.Subject.Strategy.ADMINISTRATIVE_NUMBER, true);
    private static final AccountLinkingPolicy JIT = new AccountLinkingPolicy(true, true);
    private static final AccountLinkingPolicy NO_JIT = new AccountLinkingPolicy(true, false);

    private WalletLinkService links;
    private WalletSubjectResolver resolver;
    private JdbcTemplate jdbc;
    private PlatformTransactionManager transactions;
    private E2eSeed seed;
    private String realm;
    private String alias;

    @BeforeEach
    void setUp() {
        links = context.getBean(WalletLinkService.class);
        resolver = context.getBean(WalletSubjectResolver.class);
        jdbc = context.getBean(JdbcTemplate.class);
        transactions = context.getBean(PlatformTransactionManager.class);
        seed = new E2eSeed(context);
        realm = E2eSeed.unique("wlink");
        alias = E2eSeed.unique("wallet");
        seed.realm(realm);
    }

    private String user(final String name) {
        return seed.user(realm, E2eSeed.unique(name), "Correct-Horse-9-Battery").userId();
    }

    private static MatchedPresentations pid(final String given, final String family, final String number) {
        final Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("given_name", given);
        claims.put("family_name", family);
        claims.put("birthdate", "1964-08-12");
        claims.put("issuing_country", "NL");
        if (number != null) {
            claims.put("personal_administrative_number", number);
        }
        return new MatchedPresentations(List.of(new VerifiedPresentation("dc+sd-jwt", "urn:eudi:pid:1", claims,
                "CN=PID Issuer", "1f", "VALID")), Set.of());
    }

    private WalletSubject subject(final String given, final String family, final String number) {
        return resolver.resolve(realm, pid(given, family, number), NUMBER_ELSE_LINK);
    }

    private static String value(final WalletSubject subject) {
        return subject instanceof WalletSubject.AdminNumber a ? a.value() : ((WalletSubject.Tuple) subject).value();
    }

    private List<Map<String, Object>> rows() {
        return new TransactionTemplate(transactions).execute(s -> jdbc.queryForList(
                "SELECT idp_alias, external_subject, user_id FROM federated_link WHERE idp_alias = ?", alias));
    }

    // ------------------------------------------------------------------------------------------- link / find / unlink

    @Test
    void link_thenFind_storesOnlyTheHmacSubjectInTheExistingFederatedLinkTable() {
        final String erika = user("erika");
        final WalletSubject tuple = subject("Erika", "Mustermann", null);
        assertThat(tuple).isInstanceOf(WalletSubject.Tuple.class);

        assertThat(links.link(realm, erika, alias, tuple)).isEqualTo(WalletLinkService.LinkResult.LINKED);

        assertThat(links.find(realm, alias, tuple)).contains(erika);
        assertThat(rows()).singleElement().satisfies(row -> {
            assertThat(row.get("external_subject")).isEqualTo(value(tuple));
            assertThat(row.get("user_id")).isEqualTo(erika);
            assertThat(row.toString()).doesNotContain("Erika").doesNotContain("Mustermann").doesNotContain("1964");
        });
    }

    @Test
    void relinkingTheSameUser_isANoOp() {
        final String erika = user("erika");
        final WalletSubject tuple = subject("Erika", "Mustermann", null);
        links.link(realm, erika, alias, tuple);

        assertThat(links.link(realm, erika, alias, tuple)).isEqualTo(WalletLinkService.LinkResult.ALREADY_LINKED);
        assertThat(rows()).hasSize(1);
    }

    @Test
    void aSubjectLinkedToAnotherUser_isRefused_andTheFirstLinkStays() {
        final String erika = user("erika");
        final String mallory = user("mallory");
        final WalletSubject tuple = subject("Erika", "Mustermann", null);
        links.link(realm, erika, alias, tuple);

        assertThat(links.link(realm, mallory, alias, tuple))
                .isEqualTo(WalletLinkService.LinkResult.LINKED_TO_ANOTHER_USER);
        assertThat(links.find(realm, alias, tuple)).contains(erika);
    }

    @Test
    void concurrentLinksOfOneSubjectByTwoUsers_onlyOneWins() throws Exception {
        final String erika = user("erika");
        final String mallory = user("mallory");
        final WalletSubject tuple = subject("Erika", "Mustermann", null);
        final ExecutorService pool = Executors.newFixedThreadPool(2);
        final CountDownLatch start = new CountDownLatch(1);
        try {
            final List<Future<WalletLinkService.LinkResult>> results = new ArrayList<>();
            for (final String userId : List.of(erika, mallory)) {
                final Callable<WalletLinkService.LinkResult> call = () -> {
                    start.await();
                    return links.link(realm, userId, alias, tuple);
                };
                results.add(pool.submit(call));
            }
            start.countDown();
            final List<WalletLinkService.LinkResult> outcomes = new ArrayList<>();
            for (final Future<WalletLinkService.LinkResult> result : results) {
                outcomes.add(result.get(30, TimeUnit.SECONDS));
            }
            assertThat(outcomes).containsExactlyInAnyOrder(WalletLinkService.LinkResult.LINKED,
                    WalletLinkService.LinkResult.LINKED_TO_ANOTHER_USER);
        } finally {
            pool.shutdownNow();
        }
        assertThat(rows()).hasSize(1);
    }

    @Test
    void aSecondPersonWithADifferentTuple_cannotUseTheLink() {
        final String erika = user("erika");
        links.link(realm, erika, alias, subject("Erika", "Mustermann", null));

        final WalletSubject other = subject("Erik", "Mustermann", null);

        assertThat(links.find(realm, alias, other)).isEmpty();
        assertThat(links.decide(realm, alias, other, JIT))
                .isEqualTo(new WalletLinkService.Decision.Refused(WalletSubject.Reason.LINK_REQUIRED));
    }

    @Test
    void aLinkIsInvisibleFromAnotherRealm_andOnlyRealmUsersCanBeLinked() {
        final String erika = user("erika");
        final WalletSubject tuple = subject("Erika", "Mustermann", null);
        links.link(realm, erika, alias, tuple);
        final String otherRealm = E2eSeed.unique("wlink-other");
        seed.realm(otherRealm);

        assertThat(links.find(otherRealm, alias, tuple)).isEmpty();
        assertThatThrownBy(() -> links.link(otherRealm, erika, alias, subject("Erika", "Gabler", null)))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> links.link(realm, "no-such-user", alias, subject("Erika", "Gabler", null)))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void anUnavailableSubjectCannotBeLinked() {
        final String erika = user("erika");

        assertThatThrownBy(() -> links.link(realm, erika, alias,
                new WalletSubject.Unavailable(WalletSubject.Reason.WEAK_SUBJECT_NOT_ACKNOWLEDGED)))
                .isInstanceOf(IllegalArgumentException.class);
        assertThat(rows()).isEmpty();
    }

    @Test
    void unlink_removesOnlyThisUsersWalletLinks() {
        final String erika = user("erika");
        final String hans = user("hans");
        final WalletSubject erikaTuple = subject("Erika", "Mustermann", null);
        final WalletSubject erikaNumber = subject("Erika", "Mustermann", "123");
        final WalletSubject hansTuple = subject("Hans", "Mustermann", null);
        links.link(realm, erika, alias, erikaTuple);
        links.link(realm, erika, alias, erikaNumber);
        links.link(realm, hans, alias, hansTuple);

        assertThat(links.unlink(realm, erika, alias)).isEqualTo(2);

        assertThat(links.find(realm, alias, erikaTuple)).isEmpty();
        assertThat(links.find(realm, alias, erikaNumber)).isEmpty();
        assertThat(links.find(realm, alias, hansTuple)).contains(hans);
        assertThat(links.unlink(realm, erika, alias)).isZero();
    }

    // ------------------------------------------------------------------------------------------- account decision

    @Test
    void numberPresent_noLink_jitAllowed_mayProvision() {
        final WalletSubject number = subject("Erika", "Mustermann", "123");
        assertThat(number).isInstanceOf(WalletSubject.AdminNumber.class);

        assertThat(links.decide(realm, alias, number, JIT)).isEqualTo(new WalletLinkService.Decision.Provision());
    }

    @Test
    void numberPresent_noLink_jitDisabled_isLinkRequired() {
        assertThat(links.decide(realm, alias, subject("Erika", "Mustermann", "123"), NO_JIT))
                .isEqualTo(new WalletLinkService.Decision.Refused(WalletSubject.Reason.LINK_REQUIRED));
    }

    @Test
    void numberPresent_linked_signsInAsThatUser() {
        final String erika = user("erika");
        final WalletSubject number = subject("Erika", "Mustermann", "123");
        links.link(realm, erika, alias, number);

        assertThat(links.decide(realm, alias, number, NO_JIT)).isEqualTo(new WalletLinkService.Decision.Existing(erika));
    }

    @Test
    void numberAbsent_noLink_isSubjectUnavailable_evenWhenJitIsAllowed() {
        final WalletLinkService.Decision decision = links.decide(realm, alias, subject("Erika", "Mustermann", null),
                JIT);

        assertThat(decision).isEqualTo(new WalletLinkService.Decision.Refused(WalletSubject.Reason.LINK_REQUIRED));
        assertThat(((WalletLinkService.Decision.Refused) decision).errorCode())
                .isEqualTo(WalletErrorCode.SUBJECT_UNAVAILABLE);
    }

    @Test
    void numberAbsent_linked_signsInAsTheLinkedUser() {
        final String erika = user("erika");
        final WalletSubject tuple = subject("Erika", "Mustermann", null);
        links.link(realm, erika, alias, tuple);

        assertThat(links.decide(realm, alias, tuple, JIT)).isEqualTo(new WalletLinkService.Decision.Existing(erika));
    }

    @Test
    void anUnavailableSubjectKeepsItsReason() {
        assertThat(links.decide(realm, alias,
                new WalletSubject.Unavailable(WalletSubject.Reason.WEAK_SUBJECT_NOT_ACKNOWLEDGED), JIT))
                .isEqualTo(new WalletLinkService.Decision.Refused(WalletSubject.Reason.WEAK_SUBJECT_NOT_ACKNOWLEDGED));
    }
}
