package group.mfnr.authorization.domain.workloadidentity;

/** A realm-scoped reference to a WIF credential (for get/delete by id within a realm). */
public record WorkloadIdentityCredentialRef(String realmId, String id) {
}
