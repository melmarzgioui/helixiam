/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

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

    /**
     * One external-IdP association: {@code idpAlias} + a human {@code displayName} resolved from the live provider
     * registry (null when the provider no longer exists). {@code externalSubject} is the IdP's own subject value —
     * EXCEPT for an EUDI Wallet link (Task 26), where it is always {@code null}. A wallet link's external subject is
     * the {@link io.helixiam.authorization.federation.wallet.WalletSubject} HMAC, a pseudonymous identifier derived
     * from the realm's pepper and (for the weak-tuple case) the holder's own PID attributes, not an identifier the
     * wallet issued to Helix the way an OIDC {@code sub} or SAML {@code NameID} is. Handing it back in a GDPR export
     * would (a) not actually tell the subject anything they can use — it is not the wallet's or issuer's subject,
     * just Helix's own linking key — and (b) is exactly the kind of correlation handle Art. 25 data minimisation says
     * to keep out of an export whose only purpose is showing the subject what Helix holds about them. The alias and
     * display name already say which provider the link is with; that is the whole user-facing fact.
     */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record GdprFederatedLink(String idpAlias, String externalSubject, String displayName) {
    }

    /** One login/admin audit event, if an event store is available. */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record GdprLoginEvent(String type, String detail, Long at) {
    }
}
