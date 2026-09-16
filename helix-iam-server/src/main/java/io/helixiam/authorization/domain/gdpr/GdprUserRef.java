package io.helixiam.authorization.domain.gdpr;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * Helix IAM GDPR: identifies the data subject an Art. 15/17/20 request is about (subscriber-side copy;
 * mirrors the publisher's {@code amqp.gdpr.GdprUserRef}). The realm scopes the request so a subject can
 * only ever be addressed within the realm they belong to.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record GdprUserRef(String realmId, String userId) {
}
