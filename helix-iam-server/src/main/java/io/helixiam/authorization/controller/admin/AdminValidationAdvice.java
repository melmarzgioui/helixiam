/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.controller.admin;

import jakarta.validation.ConstraintViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Turns Bean-Validation failures on the admin write APIs into a clean {@code 400 {message, fieldErrors}}
 * the console can show inline. Handled here (not thrown) so the response is written directly rather than
 * forwarded to the security-guarded {@code /error} dispatch (which redirects to login in this deployment).
 * Scoped to {@code io.helixiam.authorization.controller} so it never touches the OAuth/OIDC/SAML hot paths.
 */
@RestControllerAdvice(basePackages = "io.helixiam.authorization.controller")
public class AdminValidationAdvice {

    /** {@code @Valid @RequestBody} failures — one entry per offending field. */
    @ExceptionHandler(MethodArgumentNotValidException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public Map<String, Object> onBodyInvalid(final MethodArgumentNotValidException ex) {
        final Map<String, String> fieldErrors = new LinkedHashMap<>();
        ex.getBindingResult().getFieldErrors().forEach(fe ->
                fieldErrors.putIfAbsent(fe.getField(), fe.getDefaultMessage()));
        final String first = fieldErrors.isEmpty() ? "Validation failed."
                : fieldErrors.entrySet().iterator().next().getValue();
        return body(first, fieldErrors);
    }

    /** {@code @Validated} path/query-param violations (e.g. {@code @NotBlank} on a {@code @RequestParam}). */
    @ExceptionHandler(ConstraintViolationException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public Map<String, Object> onParamInvalid(final ConstraintViolationException ex) {
        final Map<String, String> fieldErrors = new LinkedHashMap<>();
        ex.getConstraintViolations().forEach(v -> {
            final String path = v.getPropertyPath().toString();
            final String field = path.contains(".") ? path.substring(path.lastIndexOf('.') + 1) : path;
            fieldErrors.putIfAbsent(field, v.getMessage());
        });
        final String first = fieldErrors.isEmpty() ? "Validation failed."
                : fieldErrors.entrySet().iterator().next().getValue();
        return body(first, fieldErrors);
    }

    /** Structured theming: a theme (or a legacy branding field mapped onto it) failed validation. */
    @ExceptionHandler(io.helixiam.authorization.theme.ThemeValidationException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public Map<String, Object> onThemeInvalid(final io.helixiam.authorization.theme.ThemeValidationException ex) {
        final Map<String, String> fieldErrors = ex.fieldErrors();
        final String first = fieldErrors.isEmpty() ? "The theme is not valid."
                : fieldErrors.values().iterator().next();
        return body(first, fieldErrors);
    }

    /** A messaging provider with an unknown channel or driver, or missing / invalid settings. */
    @ExceptionHandler(ProviderValidationException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public Map<String, Object> onProviderInvalid(final ProviderValidationException ex) {
        return body(ex.getMessage(), ex.fieldErrors());
    }

    /** Malformed / unparseable JSON body. */
    @ExceptionHandler(HttpMessageNotReadableException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public Map<String, Object> onUnreadable(final HttpMessageNotReadableException ex) {
        // Name the offending field when Jackson can tell (e.g. "colors.primary" given a string), never the input.
        if (ex.getCause() instanceof com.fasterxml.jackson.databind.JsonMappingException jme && !jme.getPath().isEmpty()) {
            final StringBuilder path = new StringBuilder();
            for (final com.fasterxml.jackson.databind.JsonMappingException.Reference ref : jme.getPath()) {
                if (ref.getFieldName() != null) {
                    path.append(path.isEmpty() ? "" : ".").append(ref.getFieldName());
                } else if (ref.getIndex() >= 0) {
                    path.append('[').append(ref.getIndex()).append(']');
                }
            }
            if (!path.isEmpty()) {
                final boolean unknown = jme instanceof com.fasterxml.jackson.databind.exc.UnrecognizedPropertyException;
                return body((unknown ? "Unknown field " : "Request body is malformed at ") + path + ".",
                        Map.of(path.toString(), unknown ? "Unknown field." : "Invalid value."));
            }
        }
        return body("Request body is missing or malformed.", Map.of());
    }

    private static Map<String, Object> body(final String message, final Map<String, String> fieldErrors) {
        final Map<String, Object> out = new LinkedHashMap<>();
        out.put("message", message);
        out.put("fieldErrors", fieldErrors);
        return out;
    }

    /**
     * Review rc.3 #4: a unique value already in use (an email address, a username, a name) is a {@code 409} — never
     * a 500 that exposes the database constraint.
     */
    @ExceptionHandler({io.helixiam.common.exception.DuplicateException.class,
            org.springframework.dao.DataIntegrityViolationException.class})
    @ResponseStatus(HttpStatus.CONFLICT)
    public Map<String, Object> onConflict(final RuntimeException ex) {
        return Map.of("error", "conflict", "message", "This value is already in use (for example the email address or name).");
    }
}
