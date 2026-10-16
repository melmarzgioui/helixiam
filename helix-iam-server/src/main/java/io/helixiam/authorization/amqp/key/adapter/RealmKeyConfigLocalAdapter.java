/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.amqp.key.adapter;

import tools.jackson.core.type.TypeReference;
import io.helixiam.authorization.amqp.key.RealmKeyConfigPublisher;
import io.helixiam.authorization.amqp.key.RealmKeyView;
import io.helixiam.authorization.amqp.support.DtoBridge;
import io.helixiam.authorization.domain.realm.RealmKey;
import io.helixiam.authorization.service.key.RealmKeyService;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Optional;

/**
 * Strip-RabbitMQ (Task 3): in-process adapter of {@link RealmKeyConfigPublisher}. Only public key material crosses to
 * the pub-side view.
 */
@Component
public class RealmKeyConfigLocalAdapter implements RealmKeyConfigPublisher {

    private final RealmKeyService service;
    private final DtoBridge bridge;

    public RealmKeyConfigLocalAdapter(final RealmKeyService service, final DtoBridge bridge) {
        this.service = service;
        this.bridge = bridge;
    }

    @Override
    public List<RealmKeyView> list(final String realmId) {
        return bridge.to(service.listViews(realmId), new TypeReference<List<RealmKeyView>>() { });
    }

    @Override
    public RealmKeyView rotate(final String realmId, final String algorithm) {
        return view(service.rotate(realmId, algorithm));
    }

    @Override
    public RealmKeyView importKey(final String realmId, final String privateKeyPem, final String certificateChainPem) {
        return view(service.importKey(realmId, privateKeyPem, certificateChainPem));
    }

    @Override
    public CsrView createCsr(final String realmId, final String algorithm, final String subject,
                             final List<String> dnsNames) {
        final RealmKeyService.CsrResult result = service.createCsr(realmId, algorithm, subject, dnsNames);
        return new CsrView(view(result.key()), result.csrPem());
    }

    @Override
    public Optional<String> csr(final String realmId, final String keyId) {
        return service.find(realmId, keyId).map(RealmKey::getCsrPem).filter(c -> !c.isBlank());
    }

    @Override
    public RealmKeyView attachCertificate(final String realmId, final String keyId, final String certificateChainPem) {
        return view(service.attachCertificate(realmId, keyId, certificateChainPem));
    }

    @Override
    public RealmKeyView activate(final String realmId, final String keyId, final boolean force) {
        return view(service.activate(realmId, keyId, force));
    }

    @Override
    public RetireOutcome retire(final String realmId, final String keyId) {
        return RetireOutcome.valueOf(service.retire(realmId, keyId).name());
    }

    private RealmKeyView view(final RealmKey key) {
        return bridge.to(io.helixiam.authorization.domain.realm.RealmKeyView.from(key, java.time.Instant.now(),
                service.minStaging()), RealmKeyView.class);
    }
}
