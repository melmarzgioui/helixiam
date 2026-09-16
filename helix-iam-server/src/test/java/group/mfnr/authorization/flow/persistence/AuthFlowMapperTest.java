package group.mfnr.authorization.flow.persistence;

import group.mfnr.authorization.flow.AuthExecution;
import group.mfnr.authorization.flow.AuthFlow;
import group.mfnr.authorization.flow.Requirement;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Helix IAM E2.5: rebuilds the engine's {@link AuthFlow} tree from the flat, persisted
 * {@link AuthFlowDefinition} (parentId links → nesting, priority → order, condition flag →
 * condition executions).
 */
class AuthFlowMapperTest {

    private final AuthFlowMapper mapper = new AuthFlowMapper();

    @Test
    void carriesPerExecutionConfigThroughToTheEngineExecution() {
        AuthFlowDefinition def = new AuthFlowDefinition("browser", "master", List.of(
                new AuthExecutionDefinition("e-idp", null, "idp-redirect", "REQUIRED", false, 10,
                        java.util.Map.of("providerAlias", "digid", "mode", "REDIRECT"))));

        AuthFlow flow = mapper.toAuthFlow(def);

        assertThat(flow.executions().get(0).config())
                .containsEntry("providerAlias", "digid")
                .containsEntry("mode", "REDIRECT");
    }

    @Test
    void mapsTopLevelExecutionsInPriorityOrder() {
        AuthFlowDefinition def = new AuthFlowDefinition("browser", "master", List.of(
                new AuthExecutionDefinition("e-otp", null, "otp", "REQUIRED", false, 20),
                new AuthExecutionDefinition("e-pass", null, "password", "REQUIRED", false, 10)));

        AuthFlow flow = mapper.toAuthFlow(def);

        assertThat(flow.id()).isEqualTo("browser");
        assertThat(flow.executions()).extracting(AuthExecution::id).containsExactly("e-pass", "e-otp");
        assertThat(flow.executions().get(0).authenticatorId()).isEqualTo("password");
        assertThat(flow.executions().get(0).requirement()).isEqualTo(Requirement.REQUIRED);
    }

    @Test
    void rebuildsAConditionalSubflowWithItsConditionAndStep() {
        AuthFlowDefinition def = new AuthFlowDefinition("browser", "master", List.of(
                new AuthExecutionDefinition("e-pass", null, "password", "REQUIRED", false, 10),
                new AuthExecutionDefinition("e-stepup", null, null, "CONDITIONAL", false, 20),
                new AuthExecutionDefinition("c-risk", "e-stepup", "risk-high", "REQUIRED", true, 10),
                new AuthExecutionDefinition("e-otp", "e-stepup", "otp", "REQUIRED", false, 20)));

        AuthFlow flow = mapper.toAuthFlow(def);

        assertThat(flow.executions()).extracting(AuthExecution::id).containsExactly("e-pass", "e-stepup");
        AuthExecution stepUp = flow.executions().get(1);
        assertThat(stepUp.requirement()).isEqualTo(Requirement.CONDITIONAL);
        assertThat(stepUp.isSubFlow()).isTrue();
        assertThat(stepUp.subFlow().executions()).extracting(AuthExecution::id).containsExactly("c-risk", "e-otp");
        assertThat(stepUp.subFlow().findExecution("c-risk").orElseThrow().isCondition()).isTrue();
        assertThat(stepUp.subFlow().findExecution("e-otp").orElseThrow().isCondition()).isFalse();
    }

    @Test
    void emptyOrNullDefinition_isAnEmptyFlow() {
        assertThat(mapper.toAuthFlow(new AuthFlowDefinition("browser", "master", List.of())).executions()).isEmpty();
        assertThat(mapper.toAuthFlow(null)).isNull();
    }
}
