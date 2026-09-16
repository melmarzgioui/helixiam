package group.mfnr.authorization.idp.scim;

import com.fasterxml.jackson.annotation.JsonInclude;

import java.util.List;

/**
 * Helix IAM E7 (SCIM 2.0): a SCIM error response (RFC 7644 §3.12) — {@code {schemas:[...Error], status,
 * scimType, detail}}. {@code status} is a string per the spec.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record ScimError(List<String> schemas, String status, String scimType, String detail) {

    public static ScimError of(final int status, final String detail) {
        return new ScimError(List.of(ScimSchemas.ERROR), String.valueOf(status), null, detail);
    }

    public static ScimError of(final int status, final String scimType, final String detail) {
        return new ScimError(List.of(ScimSchemas.ERROR), String.valueOf(status), scimType, detail);
    }
}
