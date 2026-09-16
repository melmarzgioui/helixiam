# Adapters: `@Publisher` interfaces → in-process `*LocalAdapter`s

Strip-RabbitMQ migration, Task 3. The OAuth2/OIDC/SAML web front (former
`authorization-server-publisher`) called the domain store (former subscriber) through **38
`@Publisher` interfaces** whose methods were `@AnonymousSender(routingKey)` AMQP RPCs. Task 3 folded
the front into this module, **stripped the AMQP annotations/transport from the 38 interfaces** (they are
now plain Java interfaces with unchanged method signatures) and added **one `@Component *LocalAdapter`
per interface** that delegates directly to the same domain `@Service` the former subscriber listener
called. Publisher call sites inject the interface unchanged; Spring wires the adapter (exactly one impl
per interface).

## The two-copy-DTO bridge

The front and store each declared their own copy of every wire DTO ("two-copy DTOs": byte-identical
record shapes in different packages, kept wire-compatible by Jackson). Where an adapter method's
parameter/return DTO differs from the domain service's type, it is converted with
`DtoBridge.to(src, Target.class)` (`group.mfnr.authorization.amqp.support.DtoBridge`) — a thin wrapper
over the app's `ObjectMapper.convertValue`, the exact in-process equivalent of the serialize→deserialize
the broker did. Where the former listener *destructured* a ref (`ref.realmId()`), the adapter calls the
same accessors on the (identical) publisher record directly — no conversion. `String`/`Boolean`/
`Integer`/`List<String>`/`Set`/`Map` and shared Spring/JDK types (`RegisteredClient`, `KeyPair`,
`RSAPublicKey`) pass through directly. `RealmScopedKey.split(...)` (now
`group.mfnr.authorization.support.RealmScopedKey`) is reproduced where the listener unpacked a packed
realm+key string.

## Interface → adapter → method → service call

Unless noted, DTO params/returns are `DtoBridge`-converted between the front copy and the
`group.mfnr.authorization.domain.*` copy. "destructure" = the publisher record's accessors are read
directly. Service = the `group.mfnr.authorization.service.*` bean the former listener used.

| # | Interface | Adapter | Method → service call |
|---|---|---|---|
| 1 | `amqp.account.AccountIdentityPublisher` | `account.adapter.AccountIdentityLocalAdapter` | `list` → `FederatedLinkService.linksForUser(userId)`; `unlink` → `.unlink(ref.userId(), ref.idpAlias())` (destructure) |
| 2 | `amqp.adminrbac.AdminRbacPublisher` | `adminrbac.adapter.AdminRbacLocalAdapter` | `catalog` → `AdminRbacService.catalog()`; `roles` → `.roles(realmId)`; `set` → `.setPermissions(write)`; `effective` → `.effectivePermissions(ref.realmId(), ref.roleNames())` (destructure) |
| 3 | `amqp.agent.AgentIdentityPublisher` | `agent.adapter.AgentIdentityLocalAdapter` | `list` → `AgentIdentityAdminService.list`; `ownerReview` → `AgentOwnerReviewService.review`; `get/suspend/activate/revoke` → `.get/.suspend/.activate/.revoke(ref.realmId(), ref.id())`; `save` → `.save(dto)`; `delete` → `.delete(ref.realmId(), ref.id())`; `findByClient` → `.findByClientId(query.realmId(), query.clientId())` |
| 4 | `amqp.application.ApplicationConfigPublisher` | `application.adapter.ApplicationConfigLocalAdapter` | `save` → `ApplicationConfigService.saveOrUpdate(config)`; `list` → `.list(realmId)`; `get` → `.get(ref.realmId(), ref.name()).orElse(null)`; `delete` → `.delete(ref.realmId(), ref.name())` |
| 5 | `amqp.audit.AuditLogPublisher` | `audit.adapter.AuditLogLocalAdapter` | `record` → `AuditLogService.record(record)` then `TRUE`; `search` → `.search(query)` |
| 6 | `amqp.AuthFlowPublisher` | `amqp.adapter.AuthFlowLocalAdapter` | `retrieveBrowserFlow` → `AuthFlowService.getDefinition(realmId, BROWSER_FLOW)`; `retrieveFlowForClient` → split, `ServiceProviderService.getFlowAlias(clientId, realm)` then `AuthFlowService.getDefinitionOrBrowser(realm, alias)`. Return `domain.flow.AuthFlowDefinition` → `flow.persistence.AuthFlowDefinition` |
| 7 | `amqp.authz.AuthorizationPublisher` | `authz.adapter.AuthorizationLocalAdapter` | `getServer` → `AuthorizationAdminService.getServer(ref.realmId(), ref.clientId())`; `setServer/createScope/createResource/createPolicy/createPermission` → `.setServer/.createScope/…(write)`; `list*` → `.listScopes/.listResources/.listPolicies/.listPermissions(ref.realmId(), ref.clientId())`; `delete*` → `.deleteScope/…(ref.realmId(), ref.clientId(), ref.name())`; `evaluate` → `.evaluate(req)` |
| 8 | `amqp.authzstore.AuthorizationStorePublisher` | `authzstore.adapter.AuthorizationStoreLocalAdapter` | `save` → `AuthorizationStoreService.save(record)`; `remove` → `.remove(request→AuthorizationRemoveRequest)`; `findById` → `.findById(id)`; `findByToken` → `.findByToken(tokenKey)`; `listAll` → `.listAll()` |
| 9 | `amqp.client.ClientAdminPublisher` | `client.adapter.ClientAdminLocalAdapter` | `list` → `ClientAdminService.list(realmId)`; `get` → `.get(ref.realmId(), ref.id()).orElse(null)`; `create` → `.create(write)`; `update` → `.update(write).orElse(null)`; `delete` → `.delete(ref.realmId(), ref.id())`; `regenerate` → `.regenerateSecret(ref.realmId(), ref.id()).orElse(null)`; `reveal` → `.reveal(ref.realmId(), ref.id()).orElse(null)` |
| 10 | `amqp.clientrole.ClientRolePublisher` | `clientrole.adapter.ClientRoleLocalAdapter` | `listRoles` → `ClientRoleAdminService.listClientRoles(ref.realmId(), ref.clientId())`; `createRole` → `.createClientRole(write)`; `deleteRole` → `.deleteClientRole(ref.realmId(), ref.clientId(), ref.name())`; `listServiceAccountRoles` → `.listServiceAccountRoles(ref.realmId(), ref.clientId())`; `assignServiceAccountRole` → `.assignServiceAccountRole(write)`; `unassignServiceAccountRole` → `.unassignServiceAccountRole(ref.realmId(), ref.clientId(), ref.roleName(), ref.roleType())`; `serviceAccountRoleNames` → split, `new ArrayList<>(.serviceAccountRoleNamesForClient(realm, client))`; `serviceAccountRoles` → split, `.serviceAccountRolesForClient(realm, client)` |
| 11 | `amqp.credential.CredentialPublisher` | `credential.adapter.CredentialLocalAdapter` | `verify` → `CredentialProviderRegistry.verify(v.getType(), v.getUserId(), v.getInput())` (destructure; no bridge) |
| 12 | `amqp.device.DeviceEnrollmentPublisher` | `device.adapter.DeviceEnrollmentLocalAdapter` | `enroll` → `DeviceCredentialService.enroll(userId, deviceId, b64url(publicKey), platform, decode(attestation), decode(nonce), biometric)` (destructure + Base64URL decode; no bridge) |
| 13 | `amqp.federation.FederatedIdentityPublisher` | `federation.adapter.FederatedIdentityLocalAdapter` | `findLinkedUser` → `FederatedIdentityService.findLinkedUser(lookup.idpAlias(), lookup.externalSubject()).orElse(null)`; `findUserByEmail` → `.findUserByEmail(email).orElse(null)`; `link` → `.link(link.idpAlias(), link.externalSubject(), link.userId())` then `TRUE`; `provisionUser` → `.provisionUser(provision.email(), provision.attributes())`; `loadUser` → `.loadUser(userId)` (→ `domain.UserCredentials`) |
| 14 | `amqp.federation.IdentityProviderConfigPublisher` | `federation.adapter.IdentityProviderConfigLocalAdapter` | `save` → `IdentityProviderConfigService.saveOrUpdate(config)`; `list` → `.list(realmId)`; `get` → `.get(ref.realmId(), ref.alias()).orElse(null)`; `delete` → `.delete(ref.realmId(), ref.alias())` |
| 15 | `amqp.flow.FlowAdminPublisher` | `flow.adapter.FlowAdminLocalAdapter` | `get` → `FlowAdminService.get(realmId, "browser")`; `save` → `.save(dto)`; `list` → `.list(realmId)`; `getByAlias` → `.get(ref.realmId(), ref.alias())`; `create` → `.create(dto.realmId(), dto.alias(), dto.copyFromAlias())`; `rename` → `.rename(dto.realmId(), dto.alias(), dto.newAlias())`; `delete` (void) → `.delete(ref.realmId(), ref.alias())` |
| 16 | `amqp.gdpr.GdprPublisher` | `gdpr.adapter.GdprLocalAdapter` | `export` → `GdprAdminService.export(ref.realmId(), ref.userId())`; `erase` → `.erase(erase)`; `listConsents` → `ConsentLedgerService.list(ref.realmId(), ref.userId())`; `recordConsent` → `.record(write)`; `withdrawConsent` → `.withdraw(withdraw)` |
| 17 | `amqp.group.GroupAdminPublisher` | `group.adapter.GroupAdminLocalAdapter` | `list` → `GroupAdminService.list(realmId)`; `create` → `.create(write)`; `update` → `.update(write)`; `delete` → `.delete(ref.realmId(), ref.groupId())`; `members/addMember/removeMember/roles/assignRole/unassignRole` → `.listMembers/.addMember/.removeMember/.listRoles/.assignRole/.unassignRole(ref)` (ref converted whole) |
| 18 | `amqp.httpsession.HttpSessionStorePublisher` | `httpsession.adapter.HttpSessionStoreLocalAdapter` | `save` → `HttpSessionStoreService.save(record)`; `findById` → `.findById(sessionId)`; `deleteById` → `.deleteById(sessionId)`; `findByPrincipal` → `.findByPrincipal(name)`; `deleteByPrincipal` → `.deleteByPrincipal(name)` |
| 19 | `amqp.key.RealmKeyConfigPublisher` | `key.adapter.RealmKeyConfigLocalAdapter` | `list` → `RealmKeyService.listViews(realmId)`; `rotate` → `RealmKeyView.from(RealmKeyService.rotate(realmId))` (→ front `RealmKeyView`); `retire` → `.retire(keyId)` |
| 20 | `amqp.LoginPublisher` | `amqp.adapter.LoginLocalAdapter` | `login` → `LoginService.loginUser(loginCredentials)` (`domain.user.UserCredentials` → front `domain.UserCredentials`). `LoginCredentials` is the merged shared type |
| 21 | `amqp.mapper.ClientMapperPublisher` | `mapper.adapter.ClientMapperLocalAdapter` | `list` → `ClientMapperAdminService.list(ref.realmId(), ref.clientId())`; `create` → `.create(write)`; `update` → `.update(write).orElse(null)`; `delete` → `.delete(ref.realmId(), ref.clientId(), ref.mapperId())`; `forClient` → split, `.mappersForClient(realm, client)` |
| 22 | `amqp.messaging.MessagingAdminPublisher` | `messaging.adapter.MessagingAdminLocalAdapter` | `listProviders` → `MessagingAdminService.listProviders`; `saveProvider` → `.saveProvider(write)`; `deleteProvider` → `.deleteProvider(key.realmId(), key.channel(), key.driver())`; `enabledProviders` → `.enabledProviders(request.realmId(), request.channel())`; `listTemplates` → `.listTemplates`; `saveTemplate` → `.saveTemplate(dto)`; `registerPushToken` → `DevicePushTokenService.register(dto)`; `listPushTokens` → `.list(query.realmId(), query.userId())` |
| 23 | `amqp.mfa.MfaRecoveryPublisher` | `mfa.adapter.MfaRecoveryLocalAdapter` | `verifyAndConsume` → `RecoveryCodeService.verifyAndConsume(v.getUserId(), v.getCode())`; `generate` → `new ArrayList<>(.generate(userId, 10))` (no bridge) |
| 24 | `amqp.mfa.MfaWebAuthnPublisher` | `mfa.adapter.MfaWebAuthnLocalAdapter` | `register` → `WebAuthnService.finishRegistration(...)`; `loginResident` → `.resolveAndVerifyAssertion(...)` (destructure + Base64URL decode; no bridge) |
| 25 | `amqp.org.OrganizationAdminPublisher` | `org.adapter.OrganizationAdminLocalAdapter` | `list` → `OrganizationAdminService.list(realmId)`; `get` → `.get(ref.realmId(), ref.orgId()).orElse(null)`; `create` → `.create(write)`; `update` → `.update(write)`; `delete` → `.delete(ref.realmId(), ref.orgId())`; `members/addMember/removeMember` → `.listMembers/.addMember/.removeMember(ref)` (ref whole); `memberships` → `.membershipsForUser(userId)` |
| 26 | `amqp.realm.RealmAdminPublisher` | `realm.adapter.RealmAdminLocalAdapter` | `get` → `RealmAdminService.get(realmId)`; `save` → `.save(dto)`; `exists` → `.exists(realmId)` |
| 27 | `amqp.resource.ResourceIndicatorPublisher` | `resource.adapter.ResourceIndicatorLocalAdapter` | `allowedResourcesForClient` → split, `ResourceIndicatorService.resolveAllowedResourcesForClient(realm, client)`; `setAllowedResourcesForClient` → `.updateAllowedResources(write.realmId(), write.clientId(), write.resources())` (no bridge) |
| 28 | `amqp.risk.RiskPublisher` | `risk.adapter.RiskLocalAdapter` | `evaluateSignals` → `RiskHistoryService.evaluate(request)`; `recordLogin` → `.record(record)` then `TRUE` |
| 29 | `amqp.role.RoleAdminPublisher` | `role.adapter.RoleAdminLocalAdapter` | `list` → `RoleAdminService.list(realmId)`; `create` → `.create(ref.realmId(), ref.name())`; `delete` → `.delete(ref.realmId(), ref.roleId())`; `userRoles` → `.userRoles(ref.realmId(), ref.userId())`; `assign` → `.assign(ref.realmId(), ref.userId(), ref.roleId())`; `unassign` → `.unassign(...)`; `setDefault` → `.setDefault(ref.realmId(), ref.roleId())` |
| 30 | `amqp.saml.SamlRelyingPartyConfigPublisher` | `saml.adapter.SamlRelyingPartyConfigLocalAdapter` | `save` → `SamlRelyingPartyConfigService.saveOrUpdate(config)`; `list` → `.list(realmId)`; `get` → `.get(ref.realmId(), ref.entityId()).orElse(null)`; `delete` → `.delete(ref.realmId(), ref.entityId())` |
| 31 | `amqp.scim.ScimTargetConfigPublisher` | `scim.adapter.ScimTargetConfigLocalAdapter` | `list` → `ScimTargetAdminService.list(realmId)`; `active` → `.active(realmId)`; `save` → `.save(target)`; `delete` → `.delete(ref.realmId(), ref.id())` |
| 32 | `amqp.scope.ClaimScopePublisher` | `scope.adapter.ClaimScopeLocalAdapter` | `claims` → `ClaimScopeAdminService.listClaims`; `createClaim/updateClaim` → `.createClaim/.updateClaim(write)`; `deleteClaim` → `.deleteClaim(ref.realmId(), ref.claimId())`; `scopes` → `.listScopes(realmId)`; `scope` → `.getScope(ref.realmId(), ref.scopeId())`; `createScope` → `.createScope(write)`; `deleteScope` → `.deleteScope(ref.realmId(), ref.scopeId())`; `addClaim/removeClaim` → `.addClaim/.removeClaim(ref)` (whole); `subjectClaim` → `new SubjectClaimDto(realmId, .getSubjectClaim(realmId))`; `setSubjectClaim` → `.setSubjectClaim(write)`; `subjectForClient` → split, `.resolveSubjectClaimForClient(realm, client)` |
| 33 | `amqp.ServiceProviderPublisher` | `amqp.adapter.ServiceProviderLocalAdapter` | `save(OAuth2Authorization)` → **NO-OP (deviation, see below)**; `retrieveKeyPair` → `KeyMaterialService.activeKeyPair(realm)`; `retrieveVerificationKeys` → `new ArrayList<>(.rotatedPublicKeys(realm))`; `retrieveWebOrigins` → `new ArrayList<>(ServiceProviderService.webOriginsForRealm(realm))`; `findById` → split, `.getRegisteredClientId(id, realm)`; `findByClientId` → split, `.getRegisteredClientByClientId(clientId, realm)` (raw `null`, no sentinel) |
| 34 | `amqp.user.UserAdminPublisher` | `user.adapter.UserAdminLocalAdapter` | `list` → `UserAdminService.list(realmId)`; `get` → `.get(ref.realmId(), ref.userId()).orElse(null)`; `create` → `.create(write)`; `update` → `.update(write).orElse(null)`; `resetPassword` → `.resetPassword(reset)`; `changePassword` → `.changePassword(change)`; `delete` → `.delete(ref.realmId(), ref.userId())`; `listCredentials` → `CredentialAdminService.list(ref.userId())`; `revokeCredential` → `.revoke(ref.userId(), ref.type(), ref.id())`; `setRequiredActions` → `.setRequiredActions(dto.userId(), dto.requiredActions())`; `getRequiredActions` → `.getRequiredActions(userId)`; `clearRequiredAction` → `.clearRequiredAction(dto.userId(), dto.requiredActions())` |
| 35 | `amqp.user.UserPublisher` | `user.adapter.UserLocalAdapter` | `getClaimProfile` → `UserService.userClaims(userId)`; `selfSignup` → `.save(userCredentials, uc.getUsername())` (`UserRegister` ↔ `domain.user.UserCredentials`); `resetPasswordRequest` → `.resetPasswordRequest(userName) != null`; `resetPasswordUpdate` → `.resetPasswordUpdate(change)`; `verifyEmail` → `.verifyEmail(code)`; `enableMfa` → `.enableMfa(userId)` then `TRUE`; `getUserInRoles` → `.getUserInRoles(userId)` |
| 36 | `amqp.webhook.WebhookConfigPublisher` | `webhook.adapter.WebhookConfigLocalAdapter` | `list` → `WebhookAdminService.list(realmId)`; `active` → `.active(realmId)`; `save` → `.save(dto)`; `delete` → `.delete(ref.realmId(), ref.id())` |
| 37 | `amqp.workloadidentity.WorkloadIdentityConfigPublisher` | `workloadidentity.adapter.WorkloadIdentityConfigLocalAdapter` | `list` → `WorkloadIdentityCredentialAdminService.list(realmId)`; `get` → `.get(ref.realmId(), ref.id())`; `save` → `.save(dto)`; `delete` → `.delete(ref.realmId(), ref.id())`; `resolve` → `.resolve(query.realmId(), query.issuer(), query.subject(), query.audience()).orElse(null)` |
| 38 | `idp.provisioning.ProvisioningAdminPublisher` | `idp.provisioning.adapter.ProvisioningAdminLocalAdapter` | `getConfig` → `ProvisioningAdminService.getConfig(realmId)`; `saveConfig` → `.saveConfig(write)`; `verifyScimToken` → `.verifyScimToken(check)`; `isDcrOpen` → `.isDcrOpen(realmId)`; `issueInitialAccessToken` → `.issueInitialAccessToken(realmId)`; `consumeInitialAccessToken` → `.consumeInitialAccessToken(check.realmId(), check.token())`; `bind` → `.bind(request)`; `verifyRegistrationToken` → `.verifyRegistrationToken(check)`; `unbind` → `.unbind(check.realmId(), check.clientInternalId())` then `TRUE` |

## Deviations / unmatched

1. **`ServiceProviderPublisher.save(OAuth2Authorization)` → no-op (adapter #33).** Its former
   `@AnonymousSender("authorization.service.provider.create")` bound to the subscriber listener
   `save(ServiceProviderOAuthClient)` — an **incompatible payload type** (`OAuth2Authorization` ≠
   `ServiceProviderOAuthClient`), so there is no type-safe in-process delegation. It also has **no caller**
   in the folded web front: SAS token/authorization persistence goes through
   `AuthorizationStorePublisher` (`QueueOAuth2AuthorizationService`), and registered-client persistence is
   itself a deliberate swallow (`RegisteredClientRepositoryService.save` — "We like to swallow"). Left as a
   documented no-op. Not fake business logic — a vestigial, uncalled sender.

2. **`UserPublisher.selfSignup` / `resetPasswordUpdate`: `Validator.validate(...)` omitted (adapter #35).**
   The former listeners called `group.mfnr.subscriber.starter.validation.Validator.validate(payload,
   ValidationException.class)` (a bean-validation guard from the deleted AMQP starter, not vendored in Task
   1/2). Omitted — these endpoints are already validated at the controller layer. Behaviourally the happy
   path is unchanged; only the redundant re-validation guard is gone.

3. **`ServiceProvider` not-found sentinel dropped (adapter #33).** The former subscriber returned a
   `RegisteredClient` sentinel (`RealmScopedKey.NOT_FOUND_CLIENT_ID`) instead of `null`, purely because a
   `null` reply on a serialized AMQP request/reply queue would block the caller for the full timeout.
   In-process the adapter returns `null` directly; the caller
   (`RegisteredClientRepositoryService.unwrap`) already maps both `null` and the sentinel to `null`.

4. **`RealmScopedKey` de-duplicated.** The publisher's `amqp.RealmScopedKey` (had `pack` only) was deleted
   and its 11 importers repointed to the Task-2 `support.RealmScopedKey` (superset: `pack` + `split`),
   which the adapters also use. No behaviour change.

No sender method was left without a resolved target beyond deviation #1.
