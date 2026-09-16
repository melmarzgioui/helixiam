package io.helixiam.authorization.security.resource;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * RFC 8707 resource-indicator validation + audience resolution (pure logic).
 */
class ResourceIndicatorsTest {

    @Test
    void absoluteUriWithoutFragmentIsValid() {
        assertThat(ResourceIndicators.isValidResource("https://api.example.com")).isTrue();
        assertThat(ResourceIndicators.isValidResource("https://api.example.com/orders")).isTrue();
        assertThat(ResourceIndicators.isValidResource("urn:example:api")).isTrue();
    }

    @Test
    void fragmentIsRejected() {
        assertThat(ResourceIndicators.isValidResource("https://api.example.com/orders#frag")).isFalse();
        assertThat(ResourceIndicators.isValidResource("https://api.example.com#")).isFalse();
    }

    @Test
    void relativeOrBlankOrMalformedIsRejected() {
        assertThat(ResourceIndicators.isValidResource("/orders")).isFalse();
        assertThat(ResourceIndicators.isValidResource("api.example.com")).isFalse();
        assertThat(ResourceIndicators.isValidResource("")).isFalse();
        assertThat(ResourceIndicators.isValidResource("  ")).isFalse();
        assertThat(ResourceIndicators.isValidResource(null)).isFalse();
        assertThat(ResourceIndicators.isValidResource("ht tp://bad uri")).isFalse();
    }

    @Test
    void emptyAllowListAcceptsAny() {
        assertThat(ResourceIndicators.isAllowed("https://api.example.com", List.of())).isTrue();
        assertThat(ResourceIndicators.isAllowed("https://api.example.com", null)).isTrue();
    }

    @Test
    void allowListRejectsNonMember() {
        final Set<String> allow = Set.of("https://api.example.com");
        assertThat(ResourceIndicators.isAllowed("https://api.example.com", allow)).isTrue();
        assertThat(ResourceIndicators.isAllowed("https://other.example.com", allow)).isFalse();
    }

    @Test
    void noResourcesRequestedYieldsEmptyAudienceNotRejected() {
        final ResourceIndicators.AudienceResult r = ResourceIndicators.resolveAudience(List.of(), Set.of());
        assertThat(r.rejected()).isFalse();
        assertThat(r.audience()).isEmpty();
    }

    @Test
    void nullResourcesRequestedYieldsEmptyAudienceNotRejected() {
        final ResourceIndicators.AudienceResult r = ResourceIndicators.resolveAudience(null, Set.of());
        assertThat(r.rejected()).isFalse();
        assertThat(r.audience()).isEmpty();
    }

    @Test
    void validRequestedResourcesBecomeMutableDeduplicatedAudience() {
        final ResourceIndicators.AudienceResult r = ResourceIndicators.resolveAudience(
                List.of("https://api.example.com", "https://api.example.com", "https://b.example.com"),
                Set.of("https://api.example.com", "https://b.example.com"));
        assertThat(r.rejected()).isFalse();
        assertThat(r.audience()).containsExactly("https://api.example.com", "https://b.example.com");
        // CRITICAL: the audience must be a MUTABLE collection (SAS Jackson allowlist).
        assertThat(r.audience()).isInstanceOf(java.util.ArrayList.class);
        r.audience().add("mutation-must-not-throw");
    }

    @Test
    void fragmentResourceIsRejectedAsInvalidTarget() {
        final ResourceIndicators.AudienceResult r = ResourceIndicators.resolveAudience(
                List.of("https://api.example.com/x#frag"), Set.of());
        assertThat(r.rejected()).isTrue();
        assertThat(r.invalidResource()).isEqualTo("https://api.example.com/x#frag");
    }

    @Test
    void resourceNotInAllowListIsRejectedAsInvalidTarget() {
        final ResourceIndicators.AudienceResult r = ResourceIndicators.resolveAudience(
                List.of("https://evil.example.com"), Set.of("https://api.example.com"));
        assertThat(r.rejected()).isTrue();
        assertThat(r.invalidResource()).isEqualTo("https://evil.example.com");
    }

    @Test
    void parseAllowListSplitsCommaAndWhitespace() {
        assertThat(ResourceIndicators.parseAllowList("https://a.com, https://b.com"))
                .containsExactly("https://a.com", "https://b.com");
        assertThat(ResourceIndicators.parseAllowList("https://a.com\nhttps://b.com"))
                .containsExactly("https://a.com", "https://b.com");
        assertThat(ResourceIndicators.parseAllowList("")).isEmpty();
        assertThat(ResourceIndicators.parseAllowList(null)).isEmpty();
    }
}
