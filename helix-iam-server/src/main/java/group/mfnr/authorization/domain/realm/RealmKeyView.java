package group.mfnr.authorization.domain.realm;

/**
 * Helix IAM B8: a safe, admin-facing projection of a {@link RealmKey} for the Realm Keys console.
 *
 * <p>Deliberately carries only <b>public</b> material — the key id, algorithm, lifecycle status,
 * Base64 public key and the creation/rotation timestamps (epoch millis). The encrypted private key
 * is NEVER mapped here, so it cannot leak across the admin API.
 */
public record RealmKeyView(String keyId, String algorithm, String status, String publicKey,
                           Long createdAt, Long rotatedAt) {

    /** Maps a stored key to its public projection (drops the private key). */
    public static RealmKeyView from(final RealmKey key) {
        return new RealmKeyView(
                key.getKeyId(), key.getAlgorithm(), key.getStatus(), key.getPublicKey(),
                key.getCreationDate() == null ? null : key.getCreationDate().getTime(),
                key.getRotatedDate() == null ? null : key.getRotatedDate().getTime());
    }
}
