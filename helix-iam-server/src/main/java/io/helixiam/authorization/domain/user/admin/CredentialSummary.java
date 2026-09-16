package io.helixiam.authorization.domain.user.admin;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * Helix IAM E8.5: one enrolled authentication factor for a realm user, as the console's "Device &
 * passkeys" screen shows it. A flattened, secret-free view across every factor store (passkeys,
 * VeridPay-style devices, TOTP/HOTP authenticators, recovery codes); {@code id} + {@code type}
 * identify it for revocation. No key material is ever carried — only what is safe to display.
 *
 * @param type      factor family: "passkey" | "device" | "totp" | "hotp" | "recovery-code"
 * @param id        revocation handle within the type (credentialId / deviceId / a fixed token)
 * @param label     human title for the factor
 * @param detail    secondary descriptive line (may be blank)
 * @param createdAt enrolment time in epoch millis, or {@code null} if unknown
 * @param lastUsedAt last-used time in epoch millis, or {@code null} if never/unknown
 * @param revocable whether the console may revoke this factor
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record CredentialSummary(String type, String id, String label, String detail,
                                Long createdAt, Long lastUsedAt, boolean revocable) {
}
