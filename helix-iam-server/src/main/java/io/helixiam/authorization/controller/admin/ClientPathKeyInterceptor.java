/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.controller.admin;

import io.helixiam.authorization.domain.ServiceProviderOAuthClient;
import io.helixiam.authorization.repository.ServiceProviderRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.HandlerMapping;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

/**
 * Review rc.3 #3: the per-client sub-resources ({@code …/clients/{clientId}/mappers|roles|service-account|
 * allowed-resources|authz|token-exchange}) are stored under the OAuth client id, while the client endpoints
 * themselves use the internal id. Both forms are accepted here: an internal id of a client in the path realm is
 * translated to its client id, and a client that does not exist in the realm is a 404 — so nothing is ever
 * written under a key that no client uses.
 */
@Configuration
public class ClientPathKeyInterceptor implements HandlerInterceptor, WebMvcConfigurer {

    private final ServiceProviderRepository clients;

    public ClientPathKeyInterceptor(final ServiceProviderRepository clients) {
        this.clients = clients;
    }

    @Override
    public void addInterceptors(final InterceptorRegistry registry) {
        registry.addInterceptor(this).addPathPatterns(
                "/admin/realms/*/clients/*/mappers/**", "/admin/realms/*/clients/*/roles/**",
                "/admin/realms/*/clients/*/service-account/**", "/admin/realms/*/clients/*/allowed-resources/**",
                "/admin/realms/*/clients/*/authz/**", "/admin/realms/*/clients/*/token-exchange/**");
    }

    @Override
    @SuppressWarnings("unchecked")
    public boolean preHandle(final HttpServletRequest request, final HttpServletResponse response, final Object handler)
            throws Exception {
        final Object attribute = request.getAttribute(HandlerMapping.URI_TEMPLATE_VARIABLES_ATTRIBUTE);
        if (!(attribute instanceof Map<?, ?> raw)) {
            return true;
        }
        final Map<String, String> vars = (Map<String, String>) raw;
        final String realm = vars.get("realmId");
        final String key = vars.get("clientId");
        if (realm == null || key == null) {
            return true;
        }
        final Optional<String> clientId = resolve(realm, key);
        if (clientId.isEmpty()) {
            response.sendError(HttpServletResponse.SC_NOT_FOUND);
            return false;
        }
        if (!clientId.get().equals(key)) {
            final Map<String, String> rewritten = new LinkedHashMap<>(vars);
            rewritten.put("clientId", clientId.get());
            request.setAttribute(HandlerMapping.URI_TEMPLATE_VARIABLES_ATTRIBUTE, rewritten);
        }
        return true;
    }

    /** The client id for a path key that is either a client id or an internal id of a client in {@code realm}. */
    Optional<String> resolve(final String realm, final String key) {
        if (clients.findByClientIdAndRealmIdAndDeleted(key, realm, false).isPresent()) {
            return Optional.of(key);
        }
        return clients.findByIdAndDeleted(key, false).filter(c -> realm.equals(c.getRealmId()))
                .map(ServiceProviderOAuthClient::getClientId);
    }
}
