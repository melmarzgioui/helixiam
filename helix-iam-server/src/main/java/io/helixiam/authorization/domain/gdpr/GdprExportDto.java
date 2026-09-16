package io.helixiam.authorization.domain.gdpr;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.List;
import java.util.Map;

/**
 * Helix IAM GDPR Art. 15/20: the complete, machine-readable export of everything the platform holds about a
 * data subject (subscriber-side copy). Assembled across every store — profile, attributes, realm/org
 * memberships, roles, enrolled credentials/devices (metadata only — NO secrets), federated links, consent
 * ledger and recent login/audit events. Self-describing so it doubles as a portability bundle.
 *
 * <p><b>Secret omission:</b> this projection NEVER carries password hashes, salts, TOTP/HOTP secrets,
 * WebAuthn attestation/public keys, device public keys, recovery-code hashes, or session blobs. Credentials
 * appear as {@link GdprCredentialMeta} (type/label/timestamps) only.
 *
 * @param generatedAt epoch millis the export was assembled
 * @param schema      a stable schema tag for downstream parsers
 * @param realmId     realm the subject belongs to (the request realm)
 * @param userId      the data subject
 * @param profile     core profile fields (username, email, flags, timestamps)
 * @param attributes  arbitrary user attributes (the user_profile map)
 * @param roles       realm roles held in this realm
 * @param realmMemberships every realm the user is bound to (tenant_user links)
 * @param organizations organization memberships within the realm
 * @param credentials enrolled authentication factors, metadata only
 * @param federatedLinks external-IdP associations (idp alias + external subject)
 * @param consents    the user's consent ledger (grants + withdrawals)
 * @param loginEvents recent login/audit events if available (may be empty)
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record GdprExportDto(Long generatedAt, String schema, String realmId, String userId,
                            GdprProfile profile, Map<String, String> attributes, List<String> roles,
                            List<GdprRealmMembership> realmMemberships, List<GdprOrgMembership> organizations,
                            List<GdprCredentialMeta> credentials, List<GdprFederatedLink> federatedLinks,
                            List<GdprConsentRecordDto> consents, List<GdprLoginEvent> loginEvents) {

    /** Core profile fields — never includes the password hash, salt or MFA secret. */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record GdprProfile(String username, String email, boolean emailVerified, boolean enabled, boolean locked,
                              boolean mfaEnabled, Long createdAt) {
    }

    /** One realm the subject is bound to. */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record GdprRealmMembership(String realmId, Long joinedAt) {
    }

    /** One organization the subject belongs to within the realm. */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record GdprOrgMembership(String orgId, String name, String role) {
    }

    /** One enrolled factor — metadata only; no key material. */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record GdprCredentialMeta(String type, String id, String label, String detail, Long createdAt,
                                     Long lastUsedAt) {
    }

    /** One external-IdP association. */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record GdprFederatedLink(String idpAlias, String externalSubject) {
    }

    /** One login/admin audit event, if an event store is available. */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record GdprLoginEvent(String type, String detail, Long at) {
    }
}
