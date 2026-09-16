package io.helixiam.authorization.amqp.scope;


import java.util.List;

/**
 * Helix IAM E8.5: the Claims + Client-scopes admin API's seam onto the realm-domain store (owned by the
 * subscriber). Routing keys are single tokens (no hyphens) for unambiguous queue binding.
 */
public interface ClaimScopePublisher {

    String EXCHANGE_AUTHORIZATION_SCOPE_ADMIN = "exchange-authorization-scope-admin";
    String CLAIMS = "authorization.scope.admin.claims";
    String CREATE_CLAIM = "authorization.scope.admin.createclaim";
    String UPDATE_CLAIM = "authorization.scope.admin.updateclaim";
    String DELETE_CLAIM = "authorization.scope.admin.deleteclaim";
    String SCOPES = "authorization.scope.admin.scopes";
    String SCOPE = "authorization.scope.admin.scope";
    String CREATE_SCOPE = "authorization.scope.admin.createscope";
    String DELETE_SCOPE = "authorization.scope.admin.deletescope";
    String ADD_CLAIM = "authorization.scope.admin.addclaim";
    String REMOVE_CLAIM = "authorization.scope.admin.removeclaim";
    String SUBJECT_CLAIM = "authorization.scope.admin.subjectclaim";
    String SET_SUBJECT_CLAIM = "authorization.scope.admin.setsubjectclaim";
    String SUBJECT_FOR_CLIENT = "authorization.scope.admin.subjectforclient";

    List<ClaimDto> claims(final String realmId);

    ClaimDto createClaim(final ClaimWriteDto write);

    ClaimDto updateClaim(final ClaimWriteDto write);

    Boolean deleteClaim(final ScopeRef ref);

    List<ClientScopeDto> scopes(final String realmId);

    ScopeDetailDto scope(final ScopeRef ref);

    ClientScopeDto createScope(final ScopeWriteDto write);

    Boolean deleteScope(final ScopeRef ref);

    Boolean addClaim(final ScopeRef ref);

    Boolean removeClaim(final ScopeRef ref);

    SubjectClaimDto subjectClaim(final String realmId);

    SubjectClaimDto setSubjectClaim(final SubjectClaimDto write);

    String subjectForClient(final String clientId);
}
