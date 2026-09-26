/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.config;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.boot.web.error.ErrorAttributeOptions;
import org.springframework.boot.web.servlet.error.DefaultErrorAttributes;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.WebRequest;

import java.util.Map;
import java.util.UUID;

/**
 * 1.0 item 8: every error response carries a {@code correlationId}; a server error (5xx) is logged once with that
 * id and its stack trace, so an operator can find it. Clients never see the exception, message or stack trace
 * ({@code server.error.include-*} stay at never/false).
 */
@Component
public class CorrelatedErrorAttributes extends DefaultErrorAttributes {

    private static final Logger LOG = LogManager.getLogger(CorrelatedErrorAttributes.class);

    @Override
    public Map<String, Object> getErrorAttributes(final WebRequest webRequest, final ErrorAttributeOptions options) {
        final Map<String, Object> attributes = super.getErrorAttributes(webRequest, options);
        final String correlationId = UUID.randomUUID().toString();
        attributes.put("correlationId", correlationId);
        final Object status = attributes.get("status");
        if (status instanceof Integer code && code >= 500) {
            LOG.error("Server error {} on {} [correlationId={}]", code, attributes.get("path"), correlationId,
                    getError(webRequest));
        }
        return attributes;
    }
}
