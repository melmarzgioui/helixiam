package group.mfnr.authorization.amqp.key;

/**
 * Helix IAM B8: publisher-side copy of the subscriber's {@code RealmKeyView} (two-copy DTO,
 * same field order for Jackson-over-AMQP). Carries only public signing-key material for the
 * admin Realm Keys console — never the private key.
 */
public record RealmKeyView(String keyId, String algorithm, String status, String publicKey,
                           Long createdAt, Long rotatedAt) {
}
