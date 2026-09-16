package io.helixiam.authorization.amqp.realm;


/**
 * Helix IAM E8.5-S4: the Realm settings admin API's seam onto the realm-domain store (owned by the
 * subscriber). Routing keys are single tokens (no hyphens) for unambiguous queue binding.
 */
public interface RealmAdminPublisher {

    String EXCHANGE_AUTHORIZATION_REALM_ADMIN = "exchange-authorization-realm-admin";
    String REALM_ADMIN_GET = "authorization.realm.admin.get";
    String REALM_ADMIN_SAVE = "authorization.realm.admin.save";
    String REALM_ADMIN_EXISTS = "authorization.realm.admin.exists";

    RealmSettingsDto get(final String realmId);

    RealmSettingsDto save(final RealmSettingsDto dto);

    /**
     * Whether the realm is actually provisioned (a realm-config row exists) — the raw existence check the
     * realm-routing filter uses to 404 unknown realms, distinct from {@link #get} which synthesizes defaults.
     */
    Boolean exists(final String realmId);
}
