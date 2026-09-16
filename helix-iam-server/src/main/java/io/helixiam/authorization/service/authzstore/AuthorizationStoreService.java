package io.helixiam.authorization.service.authzstore;

import io.helixiam.authorization.domain.authzstore.HelixAuthorization;
import io.helixiam.authorization.domain.authzstore.HelixAuthorizationToken;
import io.helixiam.authorization.domain.authzstore.admin.AuthorizationRecord;
import io.helixiam.authorization.domain.authzstore.admin.AuthorizationRemoveRequest;
import io.helixiam.authorization.repository.authzstore.HelixAuthorizationRepository;
import io.helixiam.authorization.repository.authzstore.HelixAuthorizationTokenRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.List;

/**
 * Helix IAM (Q1): the subscriber-owned OAuth2 authorization (token) store, reached over AMQP so the publisher
 * needs no datasource. Stores an opaque blob keyed by id + a {@code findByToken} index keyed by the SHA-256 of
 * each code/token/state value (raw values are JWTs, too large for a btree key). Mirrors the contract of
 * {@code OAuth2AuthorizationService} (save / remove / findById / findByToken).
 */
@Service
public class AuthorizationStoreService {

    private final HelixAuthorizationRepository authorizations;
    private final HelixAuthorizationTokenRepository tokens;

    public AuthorizationStoreService(final HelixAuthorizationRepository authorizations,
                                     final HelixAuthorizationTokenRepository tokens) {
        this.authorizations = authorizations;
        this.tokens = tokens;
    }

    @Transactional
    public Boolean save(final AuthorizationRecord record) {
        final HelixAuthorization entity = authorizations.findById(record.id()).orElseGet(HelixAuthorization::new);
        entity.setId(record.id());
        entity.setPrincipalName(record.principalName());
        entity.setGrantType(record.grantType());
        entity.setBlob(record.blob());
        entity.setExpiresAt(record.expiresAtEpochMilli());
        authorizations.save(entity);
        tokens.deleteByAuthorizationId(record.id());
        if (record.tokenKeys() != null) {
            for (final String key : record.tokenKeys()) {
                final HelixAuthorizationToken token = new HelixAuthorizationToken();
                token.setTokenHash(sha256(key));
                token.setAuthorizationId(record.id());
                tokens.save(token);
            }
        }
        return true;
    }

    @Transactional
    public Boolean remove(final AuthorizationRemoveRequest request) {
        tokens.deleteByAuthorizationId(request.id());
        authorizations.findById(request.id()).ifPresent(authorizations::delete);
        return true;
    }

    public AuthorizationRecord findById(final String id) {
        return authorizations.findById(id).map(AuthorizationStoreService::toRecord).orElse(null);
    }

    /** Every stored authorization (with blobs) — for the publisher's Sessions-admin / SSO rollup. */
    public List<AuthorizationRecord> listAll() {
        return authorizations.findAll().stream().map(AuthorizationStoreService::toRecord).toList();
    }

    public AuthorizationRecord findByToken(final String tokenKey) {
        return tokens.findById(sha256(tokenKey))
                .flatMap(t -> authorizations.findById(t.getAuthorizationId()))
                .map(AuthorizationStoreService::toRecord)
                .orElse(null);
    }

    private static AuthorizationRecord toRecord(final HelixAuthorization e) {
        return new AuthorizationRecord(e.getId(), e.getPrincipalName(), e.getGrantType(), e.getBlob(),
                List.of(), e.getExpiresAt());
    }

    /** SHA-256 hex of a token value — the index key (raw token values are too large for a btree key). */
    static String sha256(final String value) {
        try {
            final MessageDigest md = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(md.digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (final Exception e) {
            throw new IllegalStateException("SHA-256 unavailable: " + e.getMessage(), e);
        }
    }
}
