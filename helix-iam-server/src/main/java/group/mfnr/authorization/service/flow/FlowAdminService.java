package group.mfnr.authorization.service.flow;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import group.mfnr.authorization.domain.flow.admin.FlowDefinitionDto;
import group.mfnr.authorization.domain.flow.admin.FlowExecutionDto;
import group.mfnr.authorization.domain.flow.admin.FlowSaveDto;
import group.mfnr.authorization.domain.flow.admin.FlowSummaryDto;
import group.mfnr.authorization.domain.realm.AuthFlowEntity;
import group.mfnr.authorization.domain.realm.AuthFlowExecutionEntity;
import group.mfnr.authorization.repository.realm.AuthFlowExecutionRepository;
import group.mfnr.authorization.repository.realm.AuthFlowRepository;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Helix IAM E8.5-S4: the Auth-flow editor's backend — reads a realm's authentication flow as a flat,
 * tree-shaped list of executions and replaces that set wholesale on save. Reuses {@link AuthFlowService}
 * to seed the built-in browser flow so a never-edited realm still has an editable flow to load.
 */
@Service
public class FlowAdminService {

    private static final Logger LOG = LogManager.getLogger(FlowAdminService.class);

    private static final TypeReference<Map<String, String>> CONFIG_TYPE = new TypeReference<>() {
    };

    private final ObjectMapper objectMapper = new ObjectMapper();

    private final AuthFlowService authFlowService;
    private final AuthFlowRepository flowRepository;
    private final AuthFlowExecutionRepository executionRepository;

    public FlowAdminService(final AuthFlowService authFlowService, final AuthFlowRepository flowRepository,
                            final AuthFlowExecutionRepository executionRepository) {
        this.authFlowService = authFlowService;
        this.flowRepository = flowRepository;
        this.executionRepository = executionRepository;
    }

    /** The realm's flow (seeding the built-in browser flow first if absent), as an editable definition. */
    @Transactional
    public FlowDefinitionDto get(final String realmId, final String alias) {
        final AuthFlowEntity flow = requireFlow(realmId, alias);
        final List<FlowExecutionDto> executions = executionRepository.findAllByFlowId(flow.getFlowId()).stream()
                .map(this::toDto)
                .toList();
        return new FlowDefinitionDto(flow.getRealmId(), flow.getAlias(), flow.isBuiltIn(), executions);
    }

    /** Replaces the flow's executions with the submitted set, then returns the reloaded definition. */
    @Transactional
    public FlowDefinitionDto save(final FlowSaveDto dto) {
        final AuthFlowEntity flow = requireFlow(dto.realmId(), dto.alias());
        executionRepository.deleteByFlowId(flow.getFlowId());
        final List<AuthFlowExecutionEntity> entities = dto.executions().stream()
                .map(x -> new AuthFlowExecutionEntity(
                        x.executionId() == null || x.executionId().isBlank() ? UUID.randomUUID().toString() : x.executionId(),
                        flow.getFlowId(), x.parentId(), x.authenticatorId(), x.requirement(), x.condition(), x.priority(),
                        writeConfig(x.config())))
                .toList();
        executionRepository.saveAll(entities);
        LOG.info("Replaced {} executions for flow {} ({}/{})", entities.size(), flow.getFlowId(), dto.realmId(), dto.alias());
        final List<FlowExecutionDto> saved = entities.stream()
                .map(this::toDto)
                .toList();
        return new FlowDefinitionDto(flow.getRealmId(), flow.getAlias(), flow.isBuiltIn(), saved);
    }

    /** All of a realm's named flows (seeding the built-in browser flow first). Backs the editor's flow picker. */
    @Transactional
    public List<FlowSummaryDto> list(final String realmId) {
        authFlowService.ensureBrowserFlow(realmId);
        return flowRepository.findAllByRealmIdOrderByCreationDateAsc(realmId).stream()
                .map(f -> new FlowSummaryDto(f.getRealmId(), f.getAlias(), f.isBuiltIn()))
                .toList();
    }

    /** Create a new (non-built-in) named flow, optionally duplicating an existing flow's steps. */
    @Transactional
    public FlowSummaryDto create(final String realmId, final String alias, final String copyFromAlias) {
        final String clean = alias == null ? "" : alias.trim();
        if (clean.isBlank()) throw new IllegalArgumentException("A flow name is required");
        if (flowRepository.findFirstByRealmIdAndAlias(realmId, clean).isPresent()) {
            throw new IllegalArgumentException("A flow named '" + clean + "' already exists in this realm");
        }
        final String flowId = UUID.randomUUID().toString();
        flowRepository.save(new AuthFlowEntity(flowId, realmId, clean, false));
        if (copyFromAlias != null && !copyFromAlias.isBlank()) {
            final AuthFlowEntity src = requireFlow(realmId, copyFromAlias);
            final List<AuthFlowExecutionEntity> srcExecs = executionRepository.findAllByFlowId(src.getFlowId());
            final Map<String, String> idMap = new HashMap<>();
            for (final AuthFlowExecutionEntity e : srcExecs) idMap.put(e.getExecutionId(), UUID.randomUUID().toString());
            executionRepository.saveAll(srcExecs.stream().map(e -> new AuthFlowExecutionEntity(
                    idMap.get(e.getExecutionId()), flowId,
                    e.getParentId() == null ? null : idMap.getOrDefault(e.getParentId(), e.getParentId()),
                    e.getAuthenticatorId(), e.getRequirement(), e.isCondition(), e.getPriority(), e.getConfig())).toList());
        }
        LOG.info("Created flow {} in realm {} (copyFrom={})", clean, realmId, copyFromAlias);
        return new FlowSummaryDto(realmId, clean, false);
    }

    /** Rename a non-built-in flow. */
    @Transactional
    public FlowSummaryDto rename(final String realmId, final String alias, final String newAlias) {
        if (AuthFlowService.BROWSER_FLOW.equals(alias)) throw new IllegalArgumentException("The built-in browser flow cannot be renamed");
        final String clean = newAlias == null ? "" : newAlias.trim();
        if (clean.isBlank()) throw new IllegalArgumentException("A flow name is required");
        if (!clean.equals(alias) && flowRepository.findFirstByRealmIdAndAlias(realmId, clean).isPresent()) {
            throw new IllegalArgumentException("A flow named '" + clean + "' already exists in this realm");
        }
        final AuthFlowEntity flow = requireFlow(realmId, alias);
        flow.setAlias(clean);
        flowRepository.save(flow);
        return new FlowSummaryDto(realmId, clean, flow.isBuiltIn());
    }

    /** Delete a non-built-in flow and its executions. */
    @Transactional
    public void delete(final String realmId, final String alias) {
        if (AuthFlowService.BROWSER_FLOW.equals(alias)) throw new IllegalArgumentException("The built-in browser flow cannot be deleted");
        final AuthFlowEntity flow = requireFlow(realmId, alias);
        executionRepository.deleteByFlowId(flow.getFlowId());
        flowRepository.delete(flow);
        LOG.info("Deleted flow {} in realm {}", alias, realmId);
    }

    private FlowExecutionDto toDto(final AuthFlowExecutionEntity e) {
        return new FlowExecutionDto(e.getExecutionId(), e.getParentId(), e.getAuthenticatorId(),
                e.getRequirement(), e.isCondition(), e.getPriority(), readConfig(e.getConfig()));
    }

    /** Serialise the per-execution config map to JSON text; {@code null} when empty (keeps rows clean). */
    private String writeConfig(final Map<String, String> config) {
        if (config == null || config.isEmpty()) {
            return null;
        }
        try {
            return objectMapper.writeValueAsString(config);
        } catch (final Exception e) {
            throw new IllegalArgumentException("Could not serialise flow execution config", e);
        }
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

    /** The realm's flow, seeding the built-in browser flow on first access so there is always one to edit. */
    private AuthFlowEntity requireFlow(final String realmId, final String alias) {
        if (AuthFlowService.BROWSER_FLOW.equals(alias)) {
            authFlowService.ensureBrowserFlow(realmId);
        }
        return flowRepository.findFirstByRealmIdAndAlias(realmId, alias)
                .orElseThrow(() -> new IllegalArgumentException("No flow " + alias + " in realm " + realmId));
    }
}
