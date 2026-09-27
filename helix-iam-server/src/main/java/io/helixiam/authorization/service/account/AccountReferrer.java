/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.service.account;

import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Component;

import java.io.Serializable;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Collection;
import java.util.Locale;
import java.util.Optional;

/**
 * B1: the account console's "back to the app" link. An application opens the console with
 * {@code ?referrer=<client_id>&referrer_uri=<address>}; the link is shown only when the client exists in this realm and
 * the address is an absolute {@code http(s)} URL on the origin of one of the client's registered redirect URIs. It is
 * only ever rendered as a link the user clicks — the console never redirects to it — so it cannot be used as an open
 * redirect, and anything else (another host, port or scheme, {@code javascript:}, credentials in the URL, a relative
 * path) is ignored.
 */
@Component
public class AccountReferrer {

    /** The longest {@code referrer_uri} taken. */
    static final int MAX_URI_LENGTH = 2048;

    /** A validated return link: the application's name and the address to go back to. */
    public record Link(String clientId, String label, String uri) implements Serializable {
    }

    private final RegisteredClientRepository clients;

    public AccountReferrer(final RegisteredClientRepository clients) {
        this.clients = clients;
    }

    /**
     * The return link for {@code clientId} + {@code uri} in the current realm (the realm context must be set), or empty
     * when either is missing or does not check out.
     */
    public Optional<Link> resolve(final String clientId, final String uri) {
        if (clientId == null || clientId.isBlank() || clientId.length() > 255 || uri == null) {
            return Optional.empty();
        }
        final RegisteredClient client;
        try {
            client = clients.findByClientId(clientId);
        } catch (final RuntimeException e) {
            return Optional.empty();
        }
        if (client == null || !allowed(uri, client.getRedirectUris())) {
            return Optional.empty();
        }
        return Optional.of(new Link(client.getClientId(), label(client.getClientName(), client.getClientId(), client.getId()),
                URI.create(uri).toString()));
    }

    /** True when {@code uri} is an absolute http(s) URL whose origin is the origin of one of {@code redirectUris}. */
    public static boolean allowed(final String uri, final Collection<String> redirectUris) {
        if (uri == null || uri.isEmpty() || uri.length() > MAX_URI_LENGTH || redirectUris == null) {
            return false;
        }
        final String origin = origin(uri);
        return origin != null && redirectUris.stream().map(AccountReferrer::origin).anyMatch(origin::equals);
    }

    /** What the link says: the client's name, or its client id when the name is empty or just its internal id. */
    public static String label(final String clientName, final String clientId, final String internalId) {
        if (clientName == null || clientName.isBlank() || clientName.equals(internalId)) {
            return clientId;
        }
        return clientName;
    }

    /** {@code scheme://host:port} of an absolute http(s) URL without credentials, lower-cased; null otherwise. */
    static String origin(final String value) {
        if (value == null) {
            return null;
        }
        try {
            final URI uri = new URI(value);
            final String scheme = uri.getScheme() == null ? null : uri.getScheme().toLowerCase(Locale.ROOT);
            if (!"https".equals(scheme) && !"http".equals(scheme)) {
                return null;
            }
            if (uri.getHost() == null || uri.getRawUserInfo() != null || uri.isOpaque()) {
                return null;
            }
            final int port = uri.getPort() != -1 ? uri.getPort() : "https".equals(scheme) ? 443 : 80;
            return scheme + "://" + uri.getHost().toLowerCase(Locale.ROOT) + ":" + port;
        } catch (final URISyntaxException e) {
            return null;
        }
    }
}
