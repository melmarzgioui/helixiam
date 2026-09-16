package io.helixiam.common.exception;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.ConstraintViolation;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

/**
 * Vendored from io.helixiam.subscriber.starter.validation.exception.ValidationException.
 * Not in the Task 1 file list; pulled in transitively because
 * io.helixiam.persistence.exception.DatabaseException/DatabaseExceptionHandler
 * (both explicitly on the Task 1 list) extend it.
 *
 * Deviation: the original extends {@code org.springframework.amqp.AmqpRejectAndDontRequeueException}
 * (a RabbitMQ type) so a failed AMQP listener would reject-and-not-requeue the message. HelixIAM has
 * no broker, so this now extends plain {@link RuntimeException} instead. See VENDOR-MAP.md.
 */
public class ValidationException extends RuntimeException implements AbstractValidationException {

    @JsonProperty("hasException")
    private static final boolean HAS_EXCEPTION = true;

    @Override
    public synchronized Throwable fillInStackTrace() {
        return this;
    }

    @JsonProperty
    private final Map<String, String> validation = new HashMap<>();

    @JsonProperty
    private int errorCode = 400;

    @JsonProperty("authorization")
    private boolean authorization = false;

    public ValidationException() {
        super("Validation error");
    }

    public ValidationException(final String message) {
        super(message);
    }

    public ValidationException(final String message, final int errorCode) {
        super(message);
        this.errorCode = errorCode;
    }

    public ValidationException(final String message, final String fieldName, final String fieldErrorDescription) {
        this(message, fieldName, fieldErrorDescription,  400);
    }

    public ValidationException(final String message, final String fieldName, final String fieldErrorDescription, final int errorCode) {
        super(message);
        this.errorCode = errorCode;
        validation.put(fieldName, fieldErrorDescription);
    }

    @Override
    public void handleViolation(final Set<ConstraintViolation<Object>> validationSet) {
        for (final ConstraintViolation<Object> validationViolation : validationSet) {
            validation.put(validationViolation.getPropertyPath().toString(), validationViolation.getMessage());
        }
    }

    public int getErrorCode() {
        return errorCode;
    }

    public void setAuthorization(final boolean authorization) {
        this.authorization = authorization;
    }

    public boolean isAuthorization() {
        return authorization;
    }

    public Map<String, String> getValidation() {
        return validation;
    }
}
