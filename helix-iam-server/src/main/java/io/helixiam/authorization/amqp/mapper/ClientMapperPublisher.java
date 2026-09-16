/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.amqp.mapper;


import java.util.List;

/**
 * Helix IAM (Wave 3): the per-client protocol mapper admin API's seam onto the client-domain store (owned by
 * the subscriber). {@link #forClient} is the runtime lookup the token customizer uses at issuance. Routing keys
 * are single tokens (no hyphens) for unambiguous queue binding.
 */
public interface ClientMapperPublisher {

    String EXCHANGE_AUTHORIZATION_CLIENT_MAPPER = "exchange-authorization-client-mapper";
    String MAPPER_LIST = "authorization.client.mapper.list";
    String MAPPER_CREATE = "authorization.client.mapper.create";
    String MAPPER_UPDATE = "authorization.client.mapper.update";
    String MAPPER_DELETE = "authorization.client.mapper.delete";
    String MAPPER_FOR_CLIENT = "authorization.client.mapper.forclient";

    List<ProtocolMapperDto> list(final MapperRef ref);

    ProtocolMapperDto create(final ProtocolMapperWriteDto write);

    ProtocolMapperDto update(final ProtocolMapperWriteDto write);

    Boolean delete(final MapperRef ref);

    /** The mappers configured for an OAuth client (by its {@code client_id}); empty when none / unknown. */
    List<ProtocolMapperDto> forClient(final String clientId);
}
