package group.mfnr.authorization.idp.dcr;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Helix IAM E11 (RFC 7591 §3.2.2): a client-registration error — {@code {error, error_description}} with
 * registered error codes {@code invalid_redirect_uri}, {@code invalid_client_metadata}, {@code
 * invalid_token} (RFC 7592), {@code invalid_request}.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record DcrError(@JsonProperty("error") String error,
                       @JsonProperty("error_description") String errorDescription) {

    public static DcrError of(final String error, final String description) {
        return new DcrError(error, description);
    }
}
