package group.mfnr.authorization.service.workloadidentity;

import group.mfnr.authorization.domain.workloadidentity.WorkloadIdentityCredential;
import group.mfnr.authorization.domain.workloadidentity.WorkloadIdentityCredentialDto;
import group.mfnr.authorization.repository.workloadidentity.WorkloadIdentityCredentialRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Helix IAM WIF: CRUD over {@link WorkloadIdentityCredential} plus the runtime resolution the token
 * exchange uses — {@link #resolve} returns the enabled credential in a realm that matches a presented
 * JWT's {@code (issuer, subject, audience)} triple, or empty when none matches.
 */
@Service
public class WorkloadIdentityCredentialAdminService {

    private final WorkloadIdentityCredentialRepository repository;

    public WorkloadIdentityCredentialAdminService(final WorkloadIdentityCredentialRepository repository) {
        this.repository = repository;
    }

    @Transactional(readOnly = true)
    public List<WorkloadIdentityCredentialDto> list(final String realmId) {
        return repository.findAllByRealmIdOrderByCreationDateAsc(realmId).stream()
                .map(WorkloadIdentityCredentialDto::from).toList();
    }

    @Transactional(readOnly = true)
    public WorkloadIdentityCredentialDto get(final String realmId, final String id) {
        return repository.findById(id)
                .filter(c -> realmId.equals(c.getRealmId()))
                .map(WorkloadIdentityCredentialDto::from)
                .orElse(null);
    }

    @Transactional
    public WorkloadIdentityCredentialDto save(final WorkloadIdentityCredentialDto dto) {
        final WorkloadIdentityCredential entity = (dto.id() == null || dto.id().isBlank())
                ? new WorkloadIdentityCredential()
                : repository.findById(dto.id()).orElseGet(WorkloadIdentityCredential::new);
        if (entity.getId() == null) {
            entity.setId(UUID.randomUUID().toString());
        }
        entity.setRealmId(dto.realmId());
        entity.setName(dto.name());
        entity.setIssuer(trimSlash(dto.issuer()));
        entity.setJwksUri(blankToNull(dto.jwksUri()));
        entity.setSubject(dto.subject());
        entity.setAudience(dto.audience());
        entity.setClientId(dto.clientId());
        entity.setScopes(blankToNull(dto.scopes()));
        entity.setEnabled(dto.enabled());
        return WorkloadIdentityCredentialDto.from(repository.save(entity));
    }

    @Transactional
    public boolean delete(final String realmId, final String id) {
        final Optional<WorkloadIdentityCredential> found = repository.findById(id)
                .filter(c -> realmId.equals(c.getRealmId()));
        found.ifPresent(repository::delete);
        return found.isPresent();
    }

    /**
     * Resolve the credential that authorizes a workload token: enabled, realm-scoped, issuer + subject +
     * audience all an exact match. Returns empty when no credential matches (the exchange then fails with
     * a generic error — no enumeration of which part didn't match).
     */
    @Transactional(readOnly = true)
    public Optional<WorkloadIdentityCredentialDto> resolve(final String realmId, final String issuer,
                                                           final String subject, final String audience) {
        return repository.findAllByRealmIdAndIssuerAndEnabledTrue(realmId, trimSlash(issuer)).stream()
                .filter(c -> c.getSubject().equals(subject) && c.getAudience().equals(audience))
                .findFirst()
                .map(WorkloadIdentityCredentialDto::from);
    }

    private static String blankToNull(final String s) {
        return (s == null || s.isBlank()) ? null : s;
    }

    private static String trimSlash(final String s) {
        if (s == null) {
            return null;
        }
        return s.endsWith("/") ? s.substring(0, s.length() - 1) : s;
    }
}
