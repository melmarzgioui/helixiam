package io.helixiam.authorization.amqp.audit;

/** Helix IAM B3: publisher-side copy of a paged, filtered audit query. */
public record AuditQuery(String realm, String type, String actor, String outcome, String category,
                         int page, int size) {
}
