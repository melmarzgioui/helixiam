/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.persistence.security;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.hibernate.Interceptor;
import org.hibernate.type.Type;
import org.springframework.boot.autoconfigure.orm.jpa.HibernatePropertiesCustomizer;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Names the entity and attribute of every encrypted column that {@link AttributeEncryption} read as plaintext
 * ({@code HELIX_DB_ENCRYPTION_MIGRATE_PLAINTEXT=true}, the migration mode for rows written before {@code DB_ENCRYPTION}
 * was set), so the operator can see which rows still need re-encrypting. A Hibernate {@link Interceptor}: on each
 * entity load it matches the loaded values, by identity, against the values the converter just returned as stored.
 * The value itself is never logged.
 */
@Component
public class PlaintextReadLogger implements Interceptor, HibernatePropertiesCustomizer {

    private static final Logger LOG = LogManager.getLogger(PlaintextReadLogger.class);

    @Override
    public void customize(final Map<String, Object> hibernateProperties) {
        hibernateProperties.put("hibernate.session_factory.interceptor", this);
    }

    @Override
    public boolean onLoad(final Object entity, final Object id, final Object[] state, final String[] propertyNames,
                          final Type[] types) {
        if (AttributeEncryption.plaintextReadsOnThisThread().isEmpty()) {
            return false;
        }
        for (final String attribute : plaintextAttributes(state, propertyNames)) {
            LOG.warn("Read a plaintext value from encrypted column {}.{} (HELIX_DB_ENCRYPTION_MIGRATE_PLAINTEXT=true); it is "
                    + "encrypted on the entity's next write", entity.getClass().getSimpleName(), attribute);
        }
        return false;
    }

    /** Drops whatever plaintext reads no entity load claimed, so nothing stays referenced from a pooled thread. */
    @Override
    public void afterTransactionCompletion(final org.hibernate.Transaction tx) {
        AttributeEncryption.clearPlaintextReads();
    }

    /**
     * The attributes whose loaded value the converter read as plaintext; each match is claimed (removed), and the
     * ThreadLocal is removed once nothing is left in it.
     */
    static List<String> plaintextAttributes(final Object[] state, final String[] propertyNames) {
        final Set<String> reads = AttributeEncryption.trackedPlaintextReads();
        if (reads == null) {
            return List.of();
        }
        final List<String> found = new ArrayList<>();
        for (int i = 0; i < state.length && i < propertyNames.length; i++) {
            if (state[i] instanceof String value && reads.remove(value)) {
                found.add(propertyNames[i]);
            }
        }
        if (reads.isEmpty()) {
            AttributeEncryption.clearPlaintextReads();
        }
        return found;
    }
}
