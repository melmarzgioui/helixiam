package io.helixiam.authorization.messaging;

import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Helix IAM notifications (N3): the message-template renderer substitutes {@code {{var}}} placeholders with
 * the supplied values, leaves unknown placeholders blank, and is whitespace-tolerant.
 */
class TemplateRendererTest {

    @Test
    void substitutesKnownVariables() {
        final String out = TemplateRenderer.render("{{realm}} code: {{code}} (valid {{ttl}})",
                Map.of("realm", "master", "code", "123456", "ttl", "5 minutes"));
        assertThat(out).isEqualTo("master code: 123456 (valid 5 minutes)");
    }

    @Test
    void toleratesWhitespaceInsidePlaceholders() {
        assertThat(TemplateRenderer.render("Hi {{ user }}", Map.of("user", "Ada"))).isEqualTo("Hi Ada");
    }

    @Test
    void blanksUnknownPlaceholders_andHandlesNulls() {
        assertThat(TemplateRenderer.render("a={{a}} b={{missing}}", Map.of("a", "1"))).isEqualTo("a=1 b=");
        assertThat(TemplateRenderer.render(null, Map.of())).isEmpty();
    }

    @Test
    void sampleVariablesCoverTheCommonPlaceholders() {
        final Map<String, String> sample = TemplateRenderer.sampleVariables("master");
        assertThat(sample).containsKeys("realm", "user", "code", "ttl", "link", "number");
        assertThat(sample.get("realm")).isEqualTo("master");
    }
}
