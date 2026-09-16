package group.mfnr.authorization.controller.admin;

import group.mfnr.authorization.controller.admin.AgentIdentityAdminController.AgentRequest;
import jakarta.validation.ConstraintViolation;
import jakarta.validation.Validation;
import jakarta.validation.Validator;
import jakarta.validation.ValidatorFactory;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Helix IAM Agent (NHI): the create/update request's Bean-Validation constraints — name + owner are
 * mandatory, the name carries no spaces, and status/auth_method only accept the known enum values. The
 * {@link AdminValidationAdvice} turns any of these violations into a 400 (it never throws out of the write
 * endpoint), so here we assert the constraints themselves fire.
 */
class AgentIdentityValidationTest {

    private static ValidatorFactory factory;
    private static Validator validator;

    @BeforeAll
    static void setUp() {
        factory = Validation.buildDefaultValidatorFactory();
        validator = factory.getValidator();
    }

    @AfterAll
    static void tearDown() {
        factory.close();
    }

    private AgentRequest req(final String name, final String owner, final String status, final String authMethod) {
        return new AgentRequest(name, "Billing Agent", "Reconciles invoices", owner, status, authMethod,
                "billing-service", "billing.read", null, true, null);
    }

    @Test
    void acceptsAValidRequest() {
        final Set<ConstraintViolation<AgentRequest>> v =
                validator.validate(req("invoices-bot", "alice@example.com", "ACTIVE", "SECRET"));
        assertThat(v).isEmpty();
    }

    @Test
    void acceptsNullStatusAndAuthMethod() {
        // null = "use the default" — only an explicitly-wrong enum value is rejected.
        final Set<ConstraintViolation<AgentRequest>> v =
                validator.validate(req("invoices-bot", "alice@example.com", null, null));
        assertThat(v).isEmpty();
    }

    @Test
    void rejectsAMissingName() {
        final Set<ConstraintViolation<AgentRequest>> v =
                validator.validate(req("  ", "alice@example.com", "ACTIVE", "SECRET"));
        assertThat(v).anyMatch(c -> c.getPropertyPath().toString().equals("name"));
    }

    @Test
    void rejectsANameWithSpaces() {
        final Set<ConstraintViolation<AgentRequest>> v =
                validator.validate(req("invoices bot", "alice@example.com", "ACTIVE", "SECRET"));
        assertThat(v).anyMatch(c -> c.getPropertyPath().toString().equals("name"));
    }

    @Test
    void rejectsAMissingOwner() {
        final Set<ConstraintViolation<AgentRequest>> v =
                validator.validate(req("invoices-bot", "", "ACTIVE", "SECRET"));
        assertThat(v).anyMatch(c -> c.getPropertyPath().toString().equals("owner"));
    }

    @Test
    void rejectsABadStatusEnum() {
        final Set<ConstraintViolation<AgentRequest>> v =
                validator.validate(req("invoices-bot", "alice@example.com", "PENDING", "SECRET"));
        assertThat(v).anyMatch(c -> c.getPropertyPath().toString().equals("status"));
    }

    @Test
    void rejectsABadAuthMethodEnum() {
        final Set<ConstraintViolation<AgentRequest>> v =
                validator.validate(req("invoices-bot", "alice@example.com", "ACTIVE", "PASSWORD"));
        assertThat(v).anyMatch(c -> c.getPropertyPath().toString().equals("authMethod"));
    }
}
