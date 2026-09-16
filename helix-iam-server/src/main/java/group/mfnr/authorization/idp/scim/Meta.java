package group.mfnr.authorization.idp.scim;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;

/** Helix IAM E7 (SCIM 2.0): the common {@code meta} attribute (RFC 7643 §3.1). */
@JsonIgnoreProperties(ignoreUnknown = true)
@JsonInclude(JsonInclude.Include.NON_NULL)
public record Meta(String resourceType, String location, String created, String lastModified) {
}
