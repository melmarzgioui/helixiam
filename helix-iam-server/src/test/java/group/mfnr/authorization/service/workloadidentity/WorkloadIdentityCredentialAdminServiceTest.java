package group.mfnr.authorization.service.workloadidentity;

import group.mfnr.authorization.domain.workloadidentity.WorkloadIdentityCredential;
import group.mfnr.authorization.domain.workloadidentity.WorkloadIdentityCredentialDto;
import group.mfnr.authorization.repository.workloadidentity.WorkloadIdentityCredentialRepository;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Helix IAM WIF: federated-credential CRUD plus the runtime {@code resolve} the token exchange depends on
 * — issuer trailing-slash normalisation, exact subject/audience matching, and the cross-realm guard.
 */
class WorkloadIdentityCredentialAdminServiceTest {

    private final WorkloadIdentityCredentialRepository repo = mock(WorkloadIdentityCredentialRepository.class);
    private final WorkloadIdentityCredentialAdminService service = new WorkloadIdentityCredentialAdminService(repo);

    private WorkloadIdentityCredentialDto dto(final String id, final String issuer) {
        return new WorkloadIdentityCredentialDto(id, "master", "k8s-prod", issuer, null,
                "system:serviceaccount:apps:billing", "helix", "billing-service", "billing.read", true, null);
    }

    private WorkloadIdentityCredential entity(final String issuer, final String subject, final String audience) {
        final WorkloadIdentityCredential c = new WorkloadIdentityCredential();
        c.setId("c1");
        c.setRealmId("master");
        c.setName("k8s-prod");
        c.setIssuer(issuer);
        c.setSubject(subject);
        c.setAudience(audience);
        c.setClientId("billing-service");
        c.setEnabled(true);
        return c;
    }

    @Test
    void save_trimsTrailingSlashOnIssuer_andAssignsId() {
        when(repo.save(any(WorkloadIdentityCredential.class))).thenAnswer(i -> i.getArgument(0));

        service.save(dto(null, "https://k8s.example/"));

        final ArgumentCaptor<WorkloadIdentityCredential> c = ArgumentCaptor.forClass(WorkloadIdentityCredential.class);
        verify(repo).save(c.capture());
        assertThat(c.getValue().getId()).isNotBlank();
        assertThat(c.getValue().getIssuer()).isEqualTo("https://k8s.example");
    }

    @Test
    void delete_isNoOpAcrossRealms() {
        final WorkloadIdentityCredential other = entity("https://k8s.example", "sub", "helix");
        other.setRealmId("other-realm");
        when(repo.findById("c1")).thenReturn(Optional.of(other));

        final boolean removed = service.delete("master", "c1");

        assertThat(removed).isFalse();
        verify(repo, never()).delete(any());
    }

    @Test
    void resolve_matchesOnIssuerSubjectAudience_normalisingTheIssuerSlash() {
        when(repo.findAllByRealmIdAndIssuerAndEnabledTrue(eq("master"), eq("https://k8s.example")))
                .thenReturn(List.of(entity("https://k8s.example", "system:serviceaccount:apps:billing", "helix")));

        final Optional<WorkloadIdentityCredentialDto> hit = service.resolve("master", "https://k8s.example/",
                "system:serviceaccount:apps:billing", "helix");

        assertThat(hit).isPresent();
        assertThat(hit.get().clientId()).isEqualTo("billing-service");
    }

    @Test
    void resolve_rejectsAWrongSubject() {
        when(repo.findAllByRealmIdAndIssuerAndEnabledTrue(eq("master"), eq("https://k8s.example")))
                .thenReturn(List.of(entity("https://k8s.example", "system:serviceaccount:apps:billing", "helix")));

        final Optional<WorkloadIdentityCredentialDto> hit = service.resolve("master", "https://k8s.example",
                "system:serviceaccount:apps:attacker", "helix");

        assertThat(hit).isEmpty();
    }

    @Test
    void resolve_rejectsAWrongAudience() {
        when(repo.findAllByRealmIdAndIssuerAndEnabledTrue(eq("master"), eq("https://k8s.example")))
                .thenReturn(List.of(entity("https://k8s.example", "system:serviceaccount:apps:billing", "helix")));

        final Optional<WorkloadIdentityCredentialDto> hit = service.resolve("master", "https://k8s.example",
                "system:serviceaccount:apps:billing", "wrong-aud");

        assertThat(hit).isEmpty();
    }
}
