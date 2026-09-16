package io.helixiam.authorization.federation;

/**
 * Helix IAM E5.1: per-realm/provider policy governing how a brokered external identity becomes a
 * local user.
 *
 * @param linkByVerifiedEmail if true, an external identity whose email is <b>verified</b> may link to
 *                            an existing local user with the same email. Never link on an unverified
 *                            email — that is an account-takeover vector.
 * @param jitProvision        if true, an otherwise-unmatched external identity is provisioned as a new
 *                            local user (just-in-time); if false, an unmatched identity is rejected.
 */
public record AccountLinkingPolicy(boolean linkByVerifiedEmail, boolean jitProvision) {

    /** Safe default: JIT-provision new users, link to an existing account only on a verified email. */
    public static AccountLinkingPolicy defaults() {
        return new AccountLinkingPolicy(true, true);
    }
}
