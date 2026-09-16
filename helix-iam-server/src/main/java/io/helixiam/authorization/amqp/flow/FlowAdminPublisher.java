package io.helixiam.authorization.amqp.flow;


/**
 * Helix IAM E8.5-S4: the Auth-flow editor's seam onto the realm-domain flow store (owned by the
 * subscriber). Routing keys are single tokens (no hyphens) for unambiguous queue binding.
 */
public interface FlowAdminPublisher {

    String EXCHANGE_AUTHORIZATION_FLOW_ADMIN = "exchange-authorization-flow-admin";
    String FLOW_ADMIN_GET = "authorization.flow.admin.get";
    String FLOW_ADMIN_SAVE = "authorization.flow.admin.save";
    String FLOW_ADMIN_LIST = "authorization.flow.admin.list";
    String FLOW_ADMIN_GETALIAS = "authorization.flow.admin.getalias";
    String FLOW_ADMIN_CREATE = "authorization.flow.admin.create";
    String FLOW_ADMIN_RENAME = "authorization.flow.admin.rename";
    String FLOW_ADMIN_DELETE = "authorization.flow.admin.delete";

    FlowDefinitionDto get(final String realmId);

    FlowDefinitionDto save(final FlowSaveDto dto);

    /** Helix IAM (named flows): every flow in the realm, for the editor's flow picker. */
    java.util.List<FlowSummaryDto> list(final String realmId);

    FlowDefinitionDto getByAlias(final FlowRefDto ref);

    FlowSummaryDto create(final FlowCreateDto dto);

    FlowSummaryDto rename(final FlowRenameDto dto);

    void delete(final FlowRefDto ref);
}
