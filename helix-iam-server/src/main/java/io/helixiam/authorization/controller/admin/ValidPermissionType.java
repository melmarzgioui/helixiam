/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.controller.admin;

import io.helixiam.authorization.service.authz.PermissionType;
import jakarta.validation.Constraint;
import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;
import jakarta.validation.Payload;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/** 1.0 item 3: a permission type must be {@code resource} or {@code scope} (any case); blank means resource. */
@Target({ElementType.FIELD, ElementType.PARAMETER, ElementType.RECORD_COMPONENT})
@Retention(RetentionPolicy.RUNTIME)
@Constraint(validatedBy = ValidPermissionType.Validator.class)
public @interface ValidPermissionType {

    String message() default "Permission type must be \"resource\" or \"scope\".";

    Class<?>[] groups() default {};

    Class<? extends Payload>[] payload() default {};

    class Validator implements ConstraintValidator<ValidPermissionType, String> {
        @Override
        public boolean isValid(final String value, final ConstraintValidatorContext context) {
            return value == null || value.isBlank() || PermissionType.parse(value).isPresent();
        }
    }
}
