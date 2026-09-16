package group.mfnr.authorization.amqp.org;


import java.util.List;

/**
 * Helix IAM Organizations: the Organizations admin API's seam onto the realm-domain org store (owned by
 * the subscriber). Mirrors {@link group.mfnr.authorization.amqp.group.GroupAdminPublisher}.
 *
 * <p>Routing keys are fully dot-delimited: the subscriber derives its binding key by replacing EVERY dash
 * in the dashed queue name with a dot, so a dash here would never bind (the RPC would hang, HTTP 000).
 */
public interface OrganizationAdminPublisher {

    String EXCHANGE_AUTHORIZATION_ORG_ADMIN = "exchange-authorization-org-admin";
    String ORG_ADMIN_LIST = "authorization.org.admin.list";
    String ORG_ADMIN_GET = "authorization.org.admin.get";
    String ORG_ADMIN_CREATE = "authorization.org.admin.create";
    String ORG_ADMIN_UPDATE = "authorization.org.admin.update";
    String ORG_ADMIN_DELETE = "authorization.org.admin.delete";
    String ORG_ADMIN_MEMBERS = "authorization.org.admin.members";
    String ORG_ADMIN_ADDMEMBER = "authorization.org.admin.addmember";
    String ORG_ADMIN_REMOVEMEMBER = "authorization.org.admin.removemember";
    String ORG_ADMIN_MEMBERSHIPS = "authorization.org.admin.memberships";

    /** All organizations in a realm. */
    List<OrgDto> list(final String realmId);

    /** A single organization, or {@code null} if none. */
    OrgDto get(final OrgRef ref);

    /** Create an organization; returns the persisted state. */
    OrgDto create(final OrgWriteDto write);

    /** Update an organization; returns the persisted state ({@code null} if absent in this realm). */
    OrgDto update(final OrgWriteDto write);

    /** Delete an organization; {@code false} if it was not in this realm. */
    Boolean delete(final OrgRef ref);

    /** The members of an organization. */
    List<OrgMemberDto> members(final OrgRef ref);

    /** Add (or re-role) a user in an organization; {@code false} if the user is not in the realm or the org is absent. */
    Boolean addMember(final OrgRef ref);

    /** Remove a user from an organization; {@code false} if they weren't a member. */
    Boolean removeMember(final OrgRef ref);

    /** A user's organization memberships for token enrichment (the {@code organizations} claim). */
    List<OrgMembershipDto> memberships(final String userId);
}
