/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.controller.admin;

import io.helixiam.authorization.security.claims.ReservedClaims;
import jakarta.validation.Constraint;
import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;
import jakarta.validation.Payload;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/** Rejects a claim name that is reserved (sub, iss, aud, roles, …) — see {@link ReservedClaims}. Null/blank passes. */
@Target({ElementType.FIELD, ElementType.RECORD_COMPONENT, ElementType.PARAMETER})
@Retention(RetentionPolicy.RUNTIME)
@Constraint(validatedBy = NotReservedClaim.Validator.class)
public @interface NotReservedClaim {

    String message() default "This claim name is reserved and cannot be set by a mapper.";

    Class<?>[] groups() default {};

    Class<? extends Payload>[] payload() default {};

    class Validator implements ConstraintValidator<NotReservedClaim, String> {
        @Override
        public boolean isValid(final String value, final ConstraintValidatorContext context) {
            return !ReservedClaims.isReserved(value);
        }
    }
}
