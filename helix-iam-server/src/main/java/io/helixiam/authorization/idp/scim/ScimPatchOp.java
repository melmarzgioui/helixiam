package io.helixiam.authorization.idp.scim;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.List;

/**
 * Helix IAM E7 (SCIM 2.0): a PATCH request body (RFC 7644 §3.5.2) — a list of {@code {op, path, value}}
 * operations. Helix supports the common Okta/Azure-AD shapes: {@code replace active}, {@code replace
 * userName}, and {@code replace name.*}.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record ScimPatchOp(List<String> schemas, List<Operation> Operations) {

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record Operation(String op, String path, Object value) {
    }
}
