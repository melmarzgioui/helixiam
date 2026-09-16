package io.helixiam.authorization.repository.workloadidentity;

import io.helixiam.authorization.domain.workloadidentity.WorkloadIdentityCredential;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface WorkloadIdentityCredentialRepository extends JpaRepository<WorkloadIdentityCredential, String> {

    List<WorkloadIdentityCredential> findAllByRealmIdOrderByCreationDateAsc(String realmId);

    /** Enabled credentials in a realm whose issuer matches — the candidate set for a token exchange. */
    List<WorkloadIdentityCredential> findAllByRealmIdAndIssuerAndEnabledTrue(String realmId, String issuer);
}
