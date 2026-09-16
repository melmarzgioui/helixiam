package io.helixiam.authorization.amqp.workloadidentity;


import java.util.List;

/**
 * Helix IAM WIF: the admin API's + token-exchange endpoint's seam onto the per-realm workload-identity
 * store (subscriber). {@code list}/{@code get}/{@code save}/{@code delete} back the console; {@code
 * resolve} is the runtime call the exchange makes after verifying a workload JWT, returning the matching
 * enabled credential (or null). All-dot routing keys for the dash→dot binding.
 */
public interface WorkloadIdentityConfigPublisher {

    String EXCHANGE_AUTHORIZATION_WORKLOAD_IDENTITY = "exchange-authorization-workload-identity";
    // The subscriber binds each @AnonymousListener key with EVERY dash turned into a dot, so the
    // subscriber's `authorization-workload-identity-list` binds as `authorization.workload.identity.list`.
    // These sender keys must therefore be ALL dots (the dash inside "workload-identity" becomes a dot too),
    // or the RPC never matches a binding and hangs (HTTP 000).
    String WIF_LIST = "authorization.workload.identity.list";
    String WIF_GET = "authorization.workload.identity.get";
    String WIF_SAVE = "authorization.workload.identity.save";
    String WIF_DELETE = "authorization.workload.identity.delete";
    String WIF_RESOLVE = "authorization.workload.identity.resolve";

    List<WorkloadIdentityCredentialDto> list(final String realmId);

    WorkloadIdentityCredentialDto get(final WorkloadIdentityCredentialRef ref);

    WorkloadIdentityCredentialDto save(final WorkloadIdentityCredentialDto dto);

    Boolean delete(final WorkloadIdentityCredentialRef ref);

    WorkloadIdentityCredentialDto resolve(final WorkloadIdentityResolveQuery query);
}
