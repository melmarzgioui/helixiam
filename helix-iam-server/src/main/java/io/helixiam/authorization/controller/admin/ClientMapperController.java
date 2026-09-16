/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.controller.admin;

import io.helixiam.authorization.amqp.mapper.ClientMapperPublisher;
import io.helixiam.authorization.amqp.mapper.MapperRef;
import io.helixiam.authorization.amqp.mapper.ProtocolMapperDto;
import io.helixiam.authorization.amqp.mapper.ProtocolMapperWriteDto;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * Helix IAM (Wave 3): admin REST API for a client's protocol mappers (the Mappers tab on the Clients screen).
 * Realm + client come from the path; {@code id} here is the client's {@code clientId}.
 */
@RestController
@RequestMapping("/admin/realms/{realmId}/clients/{clientId}/mappers")
public class ClientMapperController {

    private final ClientMapperPublisher publisher;

    public ClientMapperController(final ClientMapperPublisher publisher) {
        this.publisher = publisher;
    }

    @GetMapping
    public List<ProtocolMapperDto> list(@PathVariable final String realmId, @PathVariable final String clientId) {
        return publisher.list(new MapperRef(realmId, clientId, null));
    }

    @PostMapping
    public ResponseEntity<ProtocolMapperDto> create(@PathVariable final String realmId, @PathVariable final String clientId,
                                                    @Valid @RequestBody final MapperRequest request) {
        final ProtocolMapperDto saved = publisher.create(new ProtocolMapperWriteDto(null, realmId, clientId,
                request.name(), request.mapperType(), request.source(), request.claimName(),
                request.addToAccessToken(), request.addToIdToken()));
        return ResponseEntity.status(HttpStatus.CREATED).body(saved);
    }

    @PutMapping("/{mapperId}")
    public ResponseEntity<ProtocolMapperDto> update(@PathVariable final String realmId, @PathVariable final String clientId,
                                                    @PathVariable final String mapperId, @Valid @RequestBody final MapperRequest request) {
        final ProtocolMapperDto saved = publisher.update(new ProtocolMapperWriteDto(mapperId, realmId, clientId,
                request.name(), request.mapperType(), request.source(), request.claimName(),
                request.addToAccessToken(), request.addToIdToken()));
        return saved == null ? ResponseEntity.notFound().build() : ResponseEntity.ok(saved);
    }

    @DeleteMapping("/{mapperId}")
    public ResponseEntity<Void> delete(@PathVariable final String realmId, @PathVariable final String clientId,
                                       @PathVariable final String mapperId) {
        final boolean removed = Boolean.TRUE.equals(publisher.delete(new MapperRef(realmId, clientId, mapperId)));
        return removed ? ResponseEntity.noContent().build() : ResponseEntity.notFound().build();
    }
}
