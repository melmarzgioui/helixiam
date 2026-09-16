package group.mfnr.authorization.service.flow;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import group.mfnr.authorization.domain.flow.AuthExecutionDefinition;
import group.mfnr.authorization.domain.flow.AuthFlowDefinition;
import group.mfnr.authorization.domain.realm.AuthFlowEntity;
import group.mfnr.authorization.domain.realm.AuthFlowExecutionEntity;
import group.mfnr.authorization.repository.realm.AuthFlowExecutionRepository;
import group.mfnr.authorization.repository.realm.AuthFlowRepository;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Helix IAM E2.5: owns per-realm authentication flows. Builds the flat {@link AuthFlowDefinition}
 * the publisher consumes, and seeds the built-in "browser" flow so a fresh realm has a working,
 * editable login flow. The seeded post-password flow = a CONDITIONAL step-up gated by an
 * {@code mfa-enabled} condition that, when met, requires {@code otp} — reproducing the prior
 * behaviour as data the admin console can edit.
 */
@Service
public class AuthFlowService {

    private static final Logger LOG = LogManager.getLogger(AuthFlowService.class);

    /** Alias of the flow that drives interactive browser login. */
    public static final String BROWSER_FLOW = "browser";

    private static final TypeReference<Map<String, String>> CONFIG_TYPE = new TypeReference<>() {
    };

    private final ObjectMapper objectMapper = new ObjectMapper();

    private final AuthFlowRepository flowRepository;
    private final AuthFlowExecutionRepository executionRepository;

    public AuthFlowService(final AuthFlowRepository flowRepository,
                           final AuthFlowExecutionRepository executionRepository) {
        this.flowRepository = flowRepository;
        this.executionRepository = executionRepository;
    }

    /** The flat definition of a realm's flow, or {@code null} if the realm has no such flow. */
    public AuthFlowDefinition getDefinition(final String realmId, final String alias) {
        return flowRepository.findFirstByRealmIdAndAlias(realmId, alias)
                .map(this::toDefinition)
                .orElse(null);
    }

    /**
     * Helix IAM (named flows): resolves the login flow for a client at authentication time. Runs the
     * client's bound {@code alias} when it names an existing flow; otherwise (no override, or the bound
     * flow has since been deleted/renamed) falls back to the realm's built-in {@code browser} flow.
     */
    public AuthFlowDefinition getDefinitionOrBrowser(final String realmId, final String alias) {
        if (alias != null && !alias.isBlank()) {
            final AuthFlowDefinition bound = getDefinition(realmId, alias);
            if (bound != null) {
                return bound;
            }
        }
        return getDefinition(realmId, BROWSER_FLOW);
    }

    /** Seeds the built-in browser flow for a realm if it has none. Idempotent. */
    public void ensureBrowserFlow(final String realmId) {
        if (flowRepository.findFirstByRealmIdAndAlias(realmId, BROWSER_FLOW).isPresent()) {
            return;
        }
        final String flowId = UUID.randomUUID().toString();
        flowRepository.save(new AuthFlowEntity(flowId, realmId, BROWSER_FLOW, true));

        final String stepUpId = UUID.randomUUID().toString();
        executionRepository.saveAll(List.of(
                // CONDITIONAL step-up sub-flow.
                new AuthFlowExecutionEntity(stepUpId, flowId, null, null, "CONDITIONAL", false, 10),
                // gate: only step up when the user has MFA enabled.
                new AuthFlowExecutionEntity(UUID.randomUUID().toString(), flowId, stepUpId,
                        "mfa-enabled", "REQUIRED", true, 10),
                // the second factor, required once the gate passes.
                new AuthFlowExecutionEntity(UUID.randomUUID().toString(), flowId, stepUpId,
                        "otp", "REQUIRED", false, 20)));
        LOG.info("Seeded built-in browser flow {} for realm {}", flowId, realmId);
    }

    private AuthFlowDefinition toDefinition(final AuthFlowEntity flow) {
        final List<AuthExecutionDefinition> executions = executionRepository.findAllByFlowId(flow.getFlowId())
                .stream()
                .map(e -> new AuthExecutionDefinition(e.getExecutionId(), e.getParentId(),
                        e.getAuthenticatorId(), e.getRequirement(), e.isCondition(), e.getPriority(),
                        readConfig(e.getConfig())))
                .toList();
        return new AuthFlowDefinition(flow.getAlias(), flow.getRealmId(), executions);
    }

    /** Deserialise the per-execution config JSON text to a map ({@code Map.of()} when null/blank). */
    private Map<String, String> readConfig(final String json) {
        if (json == null || json.isBlank()) {
            return Map.of();
        }
        try {
            return objectMapper.readValue(json, CONFIG_TYPE);
        } catch (final Exception e) {
            throw new IllegalStateException("Could not deserialise flow execution config", e);
        }
    }
}
