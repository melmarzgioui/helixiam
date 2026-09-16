package io.helixiam.authorization.idp.scim;

import com.fasterxml.jackson.annotation.JsonInclude;

import java.util.List;

/**
 * Helix IAM E7 (SCIM 2.0): a SCIM ListResponse (RFC 7644 §3.4.2) — paginated query result wrapping
 * {@code Resources} with {@code totalResults}, {@code startIndex} and {@code itemsPerPage} (1-based).
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record ScimListResponse<T>(List<String> schemas, int totalResults, int startIndex, int itemsPerPage,
                                  List<T> Resources) {

    public static <T> ScimListResponse<T> of(final List<T> page, final int totalResults, final int startIndex) {
        return new ScimListResponse<>(List.of(ScimSchemas.LIST_RESPONSE), totalResults, startIndex, page.size(), page);
    }
}
