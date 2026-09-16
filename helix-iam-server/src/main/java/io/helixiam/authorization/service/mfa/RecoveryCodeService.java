/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.service.mfa;

import io.helixiam.authorization.domain.mfa.RecoveryCodeEntity;
import io.helixiam.authorization.repository.mfa.RecoveryCodeRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.UUID;

/**
 * Helix IAM E3.2: issues and verifies single-use MFA recovery codes. {@link #generate} replaces a
 * user's codes, returns the plaintext set once (the caller shows it and never persists it), and
 * stores only hashes. {@link #verifyAndConsume} burns a matching unused code.
 */
@Service
public class RecoveryCodeService {

    private static final char[] ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789".toCharArray(); // no ambiguous chars
    private static final int GROUP = 4;
    private static final int GROUPS = 2; // codes look like ABCD-2345
    private static final SecureRandom RANDOM = new SecureRandom();

    private final RecoveryCodeRepository repository;

    public RecoveryCodeService(final RecoveryCodeRepository repository) {
        this.repository = repository;
    }

    /** Replaces the user's recovery codes and returns the new plaintext set (shown once). */
    @Transactional
    public List<String> generate(final String userId, final int count) {
        repository.deleteAllByUserId(userId);
        final List<String> plaintext = new ArrayList<>(count);
        final List<RecoveryCodeEntity> entities = new ArrayList<>(count);
        while (plaintext.size() < count) {
            final String code = randomCode();
            if (plaintext.contains(code)) {
                continue;
            }
            plaintext.add(code);
            entities.add(new RecoveryCodeEntity(UUID.randomUUID().toString(), userId, hash(code)));
        }
        repository.saveAll(entities);
        return plaintext;
    }

    /** Verifies a code against the user's unused codes, burning it on success. */
    @Transactional
    public boolean verifyAndConsume(final String userId, final String code) {
        final String hash = hash(code.trim().toUpperCase());
        for (final RecoveryCodeEntity entity : repository.findAllByUserIdAndUsedFalse(userId)) {
            if (MessageDigest.isEqual(
                    entity.getCodeHash().getBytes(StandardCharsets.UTF_8),
                    hash.getBytes(StandardCharsets.UTF_8))) {
                entity.setUsed(true);
                repository.save(entity);
                return true;
            }
        }
        return false;
    }

    private String randomCode() {
        final StringBuilder code = new StringBuilder();
        for (int g = 0; g < GROUPS; g++) {
            if (g > 0) {
                code.append('-');
            }
            for (int i = 0; i < GROUP; i++) {
                code.append(ALPHABET[RANDOM.nextInt(ALPHABET.length)]);
            }
        }
        return code.toString();
    }

    private static String hash(final String code) {
        try {
            final MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return Base64.getEncoder().encodeToString(digest.digest(code.getBytes(StandardCharsets.UTF_8)));
        } catch (final Exception e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }
}
