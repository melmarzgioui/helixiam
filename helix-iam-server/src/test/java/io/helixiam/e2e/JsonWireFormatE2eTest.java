/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.e2e;

import io.helixiam.common.json.JsonMappers;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import io.helixiam.authorization.security.audit.AuditEvent;
import io.helixiam.authorization.security.webhook.WebhookDispatcher;
import org.junit.jupiter.api.Test;

import java.math.BigDecimal;
import java.net.URI;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDate;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.regex.Pattern;

import static io.helixiam.testsupport.Jackson2Fixtures.assertWritesSame;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * Jackson 3 upgrade: what clients, the console and webhook receivers get must not change. Recorded on the Jackson 2
 * line ({@code upgrade/jackson2/wire-*}):
 * <ul>
 *   <li>the application's JSON mapper (Spring MVC's request and response bodies, the audit log line, the webhook
 *       body): how it writes and reads every kind of value the API uses;</li>
 *   <li>the webhook body and its {@code X-Helix-Signature} for a fixed event, byte for byte;</li>
 *   <li>the admin API error bodies, byte for byte;</li>
 *   <li>the member order and value types of representative admin, token and userinfo responses (their values differ
 *       per run).</li>
 * </ul>
 */
class JsonWireFormatE2eTest extends AbstractE2eTest {

    private static final Pattern ISO_INSTANT =
            Pattern.compile("\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d+)?(Z|[+-]\\d{2}:\\d{2})");

    /** An enum whose {@code toString} is not its name: Jackson 3 would write {@code toString} by default. */
    enum Color {
        RED, DARK_GREEN;

        @Override
        public String toString() {
            return "color-" + name().toLowerCase(Locale.ROOT);
        }
    }

    record Nested(String zulu, String alpha, Integer count) {
    }

    /** Members deliberately out of alphabetical order (Jackson 3 sorts by default). */
    record Probe(String zeta, String alpha, Instant instant, Duration duration, Date date, LocalDate localDate,
                 OffsetDateTime offsetDateTime, Optional<String> present, Optional<String> absent, Color color,
                 String nothing, int primitive, Integer boxed, long big, double dbl, float flt, BigDecimal decimal,
                 byte[] bytes, char letter, boolean flag, URI uri, Locale locale, UUID uuid, Nested nested,
                 Map<String, Object> map, List<Object> list, Map<Color, String> enumKeys) {
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    record Sparse(String present, String absent, @JsonProperty("renamed_member") String renamed) {
    }

    /** A JavaBean: getter naming (upper-case prefixes, {@code is}-getters) differs between the Jackson lines. */
    public static final class Bean {
        public String publicField = "pf";
        private final String hidden = "h";

        public String getURL() {
            return "u";
        }

        public String getXValue() {
            return "x";
        }

        public boolean isActive() {
            return true;
        }

        public int getCount() {
            return 3;
        }

        public String hidden() {
            return hidden;
        }
    }

    record Target(String name, int primitive, Integer boxed, Instant at, Duration ttl, Color color, List<String> items) {
    }

    private ObjectMapper mapper() {
        return context.getBean(ObjectMapper.class);
    }

    private static Probe probe() {
        final Map<String, Object> map = new LinkedHashMap<>();
        map.put("z", 1);
        map.put("a", null);
        map.put("m", List.of("x", 2));
        final List<Object> list = new ArrayList<>();
        list.add("s");
        list.add(null);
        list.add(1.5);
        final Map<Color, String> enumKeys = new LinkedHashMap<>();
        enumKeys.put(Color.DARK_GREEN, "g");
        enumKeys.put(Color.RED, "r");
        return new Probe("z / \"q\" <b>&</b> Zoë   😀", "a",
                Instant.parse("2026-10-01T10:00:00.123456789Z"), Duration.ofSeconds(90, 5),
                Date.from(Instant.parse("2026-10-01T10:00:00Z")), LocalDate.of(2026, 2, 28),
                OffsetDateTime.of(2026, 10, 1, 12, 0, 0, 0, ZoneOffset.ofHours(2)), Optional.of("p"), Optional.empty(),
                Color.DARK_GREEN, null, 7, null, 12_345_678_901L, 0.1, 1.5f, new BigDecimal("1.10"),
                new byte[] {1, 2, 3, (byte) 0xff}, 'c', true, URI.create("https://a.example/p?q=1&r=2"),
                Locale.forLanguageTag("nl-NL"), UUID.fromString("00000000-0000-0000-0000-000000000001"),
                new Nested("z", "a", null), map, list, enumKeys);
    }

    @Test
    void theApplicationMapper_writesAndReadsAsBefore() throws Exception {
        final ObjectMapper m = mapper();
        final StringBuilder out = new StringBuilder();
        out.append("probe ").append(m.writeValueAsString(probe())).append('\n');
        out.append("sparse ").append(m.writeValueAsString(new Sparse("p", null, "r"))).append('\n');
        out.append("bean ").append(m.writeValueAsString(new Bean())).append('\n');
        out.append("tree ").append(m.writeValueAsString(m.readTree(
                "{\"z\":1,\"a\":1.10,\"e\":1e2,\"n\":null,\"s\":\"a/b\",\"l\":12345678901,\"bi\":123456789012345678901234567890}")))
                .append('\n');

        read(out, m, "full", "{\"name\":\"n\",\"primitive\":1,\"boxed\":2,\"at\":\"2026-10-01T10:00:00Z\","
                + "\"ttl\":\"PT1M\",\"color\":\"DARK_GREEN\",\"items\":[\"a\"]}");
        read(out, m, "unknown-member", "{\"name\":\"n\",\"surprise\":{\"x\":1}}");
        read(out, m, "null-for-primitive", "{\"primitive\":null}");
        read(out, m, "missing-primitive", "{}");
        read(out, m, "trailing-tokens", "{\"name\":\"n\"} {\"name\":\"m\"}");
        read(out, m, "enum-by-tostring", "{\"color\":\"color-red\"}");
        read(out, m, "enum-lowercase", "{\"color\":\"red\"}");
        read(out, m, "enum-index", "{\"color\":1}");
        read(out, m, "instant-epoch-seconds", "{\"at\":1790000000}");
        read(out, m, "instant-epoch-decimal", "{\"at\":1790000000.5}");
        read(out, m, "instant-offset", "{\"at\":\"2026-10-01T12:00:00+02:00\"}");
        read(out, m, "duration-number", "{\"ttl\":60}");
        read(out, m, "string-for-int", "{\"primitive\":\"5\"}");
        read(out, m, "empty-string-for-boxed", "{\"boxed\":\"\"}");
        read(out, m, "float-for-int", "{\"primitive\":1.5}");
        read(out, m, "scalar-for-list", "{\"items\":\"a\"}");
        read(out, m, "number-for-string", "{\"name\":12}");
        read(out, m, "duplicate-member", "{\"name\":\"a\",\"name\":\"b\"}");
        read(out, m, "comment", "{/*c*/\"name\":\"n\"}");
        if (io.helixiam.testsupport.Jackson2Fixtures.recording()) {
            assertWritesSame("wire-application-mapper.txt", out.toString());
        }
        // A JavaBean's getters come in the JVM's reflection order (Class#getDeclaredMethods), which is not stable
        // between runs on either Jackson line: the bean line is compared by member names and values, not order.
        assertThat(beanMembersSorted(out.toString()))
                .isEqualTo(beanMembersSorted(io.helixiam.testsupport.Jackson2Fixtures.read("wire-application-mapper.txt")));
    }

    private String beanMembersSorted(final String text) throws Exception {
        final StringBuilder out = new StringBuilder();
        for (final String line : text.split("\n", -1)) {
            if (line.startsWith("bean ")) {
                final java.util.Map<String, Object> members = new java.util.TreeMap<>(mapper().readValue(
                        line.substring("bean ".length()), new tools.jackson.core.type.TypeReference<Map<String, Object>>() { }));
                out.append("bean ").append(members).append('\n');
            } else {
                out.append(line).append('\n');
            }
        }
        return out.toString();
    }

    @Test
    void theApplicationMapper_readsWithJackson2sLimitsOrStricter() {
        final tools.jackson.core.StreamReadConstraints c = mapper().tokenStreamFactory().streamReadConstraints();
        assertThat(c.getMaxStringLength()).isEqualTo(JsonMappers.MAX_STRING_LENGTH);
        assertThat(c.getMaxNestingDepth()).isPositive().isLessThanOrEqualTo(1000);
        assertThat(c.getMaxNumberLength()).isPositive().isLessThanOrEqualTo(1000);
        assertThat(c.getMaxNameLength()).isPositive().isLessThanOrEqualTo(50_000);
    }

    @Test
    void theOutboundScimUser_isByteStable() throws Exception {
        // ScimProvisioningDispatcher sends this body to the realm's SCIM targets with the application mapper.
        assertWritesSame("wire-scim-user.json", mapper().writeValueAsString(
                io.helixiam.authorization.security.scim.ScimProvisioningClient.userResource(
                        new io.helixiam.authorization.security.scim.ScimUserView("u-1", "zoë/ünal", "zoe@example.eu",
                                true, "Zoë", "O'Brien \"Ü\""))));
    }

    @Test
    void theWebhookBodyAndSignature_areByteStable() throws Exception {
        final Map<String, String> detail = new LinkedHashMap<>();
        detail.put("username", "zoë@example.eu");
        detail.put("reason", "bad / \"credentials\" <x>");
        final AuditEvent authn = AuditEvent.authn("2026-10-01T10:00:00Z", "LOGIN_FAILURE", "monthfold", "anonymous",
                "203.0.113.7", "FAILURE", detail);
        final AuditEvent admin = AuditEvent.admin("2026-10-01T10:00:01Z", "CLIENT_CREATE", "monthfold", "u-1",
                "2001:db8::1", "client", "web", "SUCCESS");

        final String authnBody = mapper().writeValueAsString(authn);
        final String adminBody = mapper().writeValueAsString(admin);
        assertWritesSame("wire-webhook-authn.json", authnBody);
        assertWritesSame("wire-webhook-admin.json", adminBody);
        // The searchable audit store keeps the detail map as JSON text (audit_log.detail).
        assertWritesSame("wire-audit-detail.json", mapper().writeValueAsString(detail));
        assertWritesSame("wire-webhook-signatures.txt", "authn sha256=" + WebhookDispatcher.sign("s3cret", authnBody)
                + "\nadmin sha256=" + WebhookDispatcher.sign("s3cret", adminBody) + "\n");
    }

    @Test
    void adminErrorBodies_areByteStable() {
        final String realm = E2eSeed.unique("wire");
        seed().realm(realm);
        final E2eAdminSession admin = adminSession();
        final StringBuilder out = new StringBuilder();

        error(out, "malformed", admin.post("/admin/realms/" + realm + "/users", "{\"username\":"));
        error(out, "wrong-type", admin.post("/admin/realms/" + realm + "/users",
                Map.of("username", Map.of("x", 1), "password", "Passw0rd!Passw0rd")));
        error(out, "validation", admin.post("/admin/realms/" + realm + "/users", Map.of("username", "")));
        final E2eHttp.Response nullPrimitive = admin.post("/admin/realms/" + realm + "/users",
                "{\"username\":\"wire-null-locked\",\"locked\":null}");
        out.append("null-for-primitive ").append(nullPrimitive.status()).append('\n');
        error(out, "theme-unknown-field", admin.put("/admin/realms/" + realm + "/theme",
                Map.of("colors", Map.of("primry", Map.of("light", "#000000")))));
        error(out, "theme-wrong-type", admin.put("/admin/realms/" + realm + "/theme",
                Map.of("colors", Map.of("primary", "red"))));
        assertWritesSame("wire-admin-errors.txt", out.toString().replace(realm, "<realm>"));
    }

    @Test
    void representativeResponses_keepTheirMemberOrderAndTypes() {
        final String realm = E2eSeed.unique("wire");
        seed().realm(realm);
        final E2eSeed.SeededClient web = seed().confidentialClient(realm, "wire-web", List.of("openid", "profile", "email"));
        final E2eSeed.SeededClient service = seed().serviceAccountClient(realm, "wire-svc", List.of("openid"));
        final E2eSeed.SeededUser user = seed().user(realm, "wire-user", "Wire-Passw0rd!x", Map.of("department", "R&D"));
        final E2eAdminSession admin = adminSession();
        final StringBuilder out = new StringBuilder();

        shape(out, "realm-settings", admin.get("/admin/realms/" + realm + "/settings").json());
        shape(out, "user", admin.get("/admin/realms/" + realm + "/users/" + user.userId()).json());
        shape(out, "client", element(admin.get("/admin/realms/" + realm + "/clients").json(), "clientId", "wire-web"));
        shape(out, "roles", admin.get("/admin/realms/" + realm + "/roles").json());
        shape(out, "theme", admin.get("/admin/realms/" + realm + "/theme").json());
        shapeTopLevel(out, "export", admin.get("/admin/realms/" + realm + "/export").json());

        final OidcFlow oidc = oidc(realm);
        final OidcFlow.Tokens tokens = oidc.authorizationCode(web.clientId(), web.secret(), web.redirectUri(),
                user.username(), user.password(), "openid profile email");
        shape(out, "token-response", tokens.raw());
        shape(out, "userinfo", oidc.userinfo(tokens.accessToken()).json());
        shape(out, "introspection", oidc.introspect(web.clientId(), web.secret(), tokens.accessToken()));
        shape(out, "client-credentials", oidc.clientCredentials(service.clientId(), service.secret(), "openid").raw());
        shape(out, "token-error", oidc.tokenEndpoint(web.clientId(), web.secret(),
                Map.of("grant_type", "authorization_code", "code", "nope", "redirect_uri", web.redirectUri())).json());
        assertWritesSame("wire-response-shapes.txt", out.toString());
    }

    @Test
    void responseBodiesEncodeTextAsBefore() {
        // MVC writes UTF-8 bytes: how a character outside the BMP, a line separator and an escaped character reach
        // the client is part of the wire format.
        final String realm = E2eSeed.unique("wire");
        seed().realm(realm);
        final E2eSeed.SeededUser user = seed().user(realm, "wire-utf8", "Wire-Passw0rd!x",
                Map.of("note", "\uD83D\uDE00 Zoë \u2028 </script> \"q\" \\ \t /"));
        final String body = adminSession().get("/admin/realms/" + realm + "/users/" + user.userId()).body();
        final java.util.regex.Matcher m = Pattern.compile("\"attributes\":\\{[^}]*}").matcher(body);
        assertThat(m.find()).as(body).isTrue();
        assertWritesSame("wire-utf8-attributes.txt", m.group());
    }

    @Test
    void aRealmExportWrittenByTheJackson2Line_isImported() {
        final E2eAdminSession admin = adminSession();
        if (io.helixiam.testsupport.Jackson2Fixtures.recording()) {
            final String source = E2eSeed.unique("wire-export");
            seed().realm(source, "Wire Export Zoë");
            seed().confidentialClient(source, "wire-export-web", List.of("openid", "profile"));
            seed().user(source, "wire-export-user", "Wire-Passw0rd!x", Map.of("department", "R&D / Ünal"));
            admin.put("/admin/realms/" + source + "/theme", Map.of("shape", Map.of("radius", 6)));
            final Map<String, String> config = new LinkedHashMap<>();
            config.put("clientId", "helix");
            config.put("clientSecret", "wire-upstream-secret");
            config.put("issuer", "https://upstream.example");
            config.put("authorizationEndpoint", "https://upstream.example/authorize");
            config.put("tokenEndpoint", "https://upstream.example/token");
            config.put("jwksUri", "https://upstream.example/jwks");
            config.put("scopes", "openid email");
            final Map<String, Object> idp = new LinkedHashMap<>();
            idp.put("alias", "wire-upstream");
            idp.put("protocol", "oidc");
            idp.put("displayName", "Upstream Zoë / Ünal");
            idp.put("enabled", true);
            idp.put("config", config);
            assertThat(admin.post("/admin/realms/" + source + "/identity-providers", idp).status()).isEqualTo(201);
            assertThat(admin.post("/admin/realms/" + source + "/webhooks", Map.of("name", "wire-hook",
                    "url", "https://hooks.example/wire", "eventTypes", "LOGIN_SUCCESS")).status()).isLessThan(300);
            assertWritesSame("wire-realm-export.json", admin.get("/admin/realms/" + source + "/export").body());
        }
        final String target = E2eSeed.unique("wire-import");
        final E2eHttp.Response r = admin.post("/admin/realms/" + target + "/import",
                io.helixiam.testsupport.Jackson2Fixtures.read("wire-realm-export.json"));

        assertThat(r.status()).as(r.toString()).isEqualTo(200);
        assertThat(r.json().has("failed")).as(r.toString()).isFalse();
        assertThat(admin.get("/admin/realms/" + target + "/clients").body()).contains("\"wire-export-web\"");
        assertThat(admin.get("/admin/realms/" + target + "/users").body()).contains("\"wire-export-user\"")
                .contains("R&D / Ünal");
        assertThat(admin.get("/admin/realms/" + target + "/theme").json().path("shape").path("radius").asInt())
                .isEqualTo(6);
        assertThat(admin.get("/admin/realms/" + target + "/identity-providers").body()).contains("\"wire-upstream\"")
                .contains("Upstream Zoë / Ünal").contains("https://upstream.example/jwks");
        assertThat(admin.get("/admin/realms/" + target + "/webhooks").body()).contains("https://hooks.example/wire");
    }

    // ------------------------------------------------------------------------------------------------ helpers

    private static void read(final StringBuilder out, final ObjectMapper m, final String name, final String json) {
        out.append("read ").append(name).append(" -> ").append(attempt(() -> {
            final Target t = m.readValue(json, Target.class);
            return t.name() + "|" + t.primitive() + "|" + t.boxed() + "|" + t.at() + "|" + t.ttl() + "|" + t.color()
                    + "|" + t.items();
        })).append('\n');
    }

    private static String attempt(final Callable<String> c) {
        try {
            return "ok " + c.call();
        } catch (final Exception e) {
            return "refused";
        }
    }

    private static void error(final StringBuilder out, final String name, final E2eHttp.Response r) {
        out.append(name).append(' ').append(r.status()).append(' ')
                .append(r.header("Content-Type").orElse("-")).append(' ').append(r.body()).append('\n');
    }

    private static JsonNode element(final JsonNode array, final String member, final String value) {
        for (final JsonNode n : array) {
            if (value.equals(n.path(member).asText())) {
                return n;
            }
        }
        throw new AssertionError("no element with " + member + "=" + value + " in " + array);
    }

    /** Only the top-level member names in order with their value kinds (nested arrays vary with the data). */
    private static void shapeTopLevel(final StringBuilder out, final String name, final JsonNode node) {
        out.append("== ").append(name).append('\n');
        final List<String> names = new ArrayList<>();
        node.propertyNames().forEach(names::add);
        for (final String n : names) {
            out.append("$.").append(n).append(": ").append(node.get(n).getNodeType().name().toLowerCase(Locale.ROOT))
                    .append('\n');
        }
    }

    /** Member names in order with their value types; arrays by their first element. */
    private static void shape(final StringBuilder out, final String name, final JsonNode node) {
        out.append("== ").append(name).append('\n');
        walk(out, "$", node);
    }

    private static void walk(final StringBuilder out, final String path, final JsonNode node) {
        if (node.isObject()) {
            out.append(path).append(": object\n");
            final List<String> names = new ArrayList<>();
            node.propertyNames().forEach(names::add);
            for (final String n : names) {
                walk(out, path + "." + n, node.get(n));
            }
        } else if (node.isArray()) {
            out.append(path).append(": array").append(node.isEmpty() ? " (empty)" : "").append('\n');
            if (!node.isEmpty()) {
                walk(out, path + "[0]", node.get(0));
            }
        } else if (node.isTextual()) {
            out.append(path).append(": ").append(ISO_INSTANT.matcher(node.asText()).matches() ? "string(iso-instant)"
                    : "string").append('\n');
        } else if (node.isIntegralNumber()) {
            out.append(path).append(": integer\n");
        } else if (node.isNumber()) {
            out.append(path).append(": decimal\n");
        } else {
            out.append(path).append(": ").append(node.getNodeType().name().toLowerCase(Locale.ROOT)).append('\n');
        }
    }
}
