package group.mfnr.authorization.amqp.support;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.stereotype.Component;

/**
 * Strip-RabbitMQ (Task 3): the in-process replacement for the Jackson-over-AMQP marshalling that used to
 * carry a request/reply between the OAuth front (former publisher) and the domain store (former
 * subscriber).
 *
 * <p>The two former services each declared their own copy of every wire DTO ("two-copy DTOs"): e.g.
 * {@code group.mfnr.authorization.amqp.client.ClientDto} (front) and
 * {@code group.mfnr.authorization.domain.client.admin.ClientDto} (store) are byte-identical record shapes
 * in different packages, kept wire-compatible by Jackson. The AMQP transport serialized the front's copy
 * to JSON and deserialized the store's copy (and vice-versa on the reply). Now that both live in one
 * module, the {@code *LocalAdapter}s bridge the two copies with {@link ObjectMapper#convertValue} — the
 * exact in-process equivalent of that serialize→deserialize round-trip, so the mapping semantics are
 * unchanged and no field-by-field mapping (which would be error-prone) is hand-written.
 */
@Component
public class DtoBridge {

    private final ObjectMapper mapper;

    public DtoBridge(final ObjectMapper mapper) {
        this.mapper = mapper;
    }

    /** Convert {@code source} to {@code type} via the configured Jackson mapper (null-safe). */
    public <T> T to(final Object source, final Class<T> type) {
        if (source == null) {
            return null;
        }
        return mapper.convertValue(source, type);
    }

    /** Convert {@code source} to a generic {@code type} (e.g. {@code List<Dto>}) (null-safe). */
    public <T> T to(final Object source, final TypeReference<T> type) {
        if (source == null) {
            return null;
        }
        return mapper.convertValue(source, type);
    }
}
