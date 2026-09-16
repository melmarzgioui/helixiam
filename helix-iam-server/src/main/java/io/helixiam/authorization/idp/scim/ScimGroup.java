package io.helixiam.authorization.idp.scim;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;

import java.util.List;

/**
 * Helix IAM E7 (SCIM 2.0): a SCIM Group resource (RFC 7643 §4.2) — {@code displayName} + {@code members}
 * (user refs), plus {@code id}/{@code meta}.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
@JsonInclude(JsonInclude.Include.NON_NULL)
public record ScimGroup(List<String> schemas, String id, String displayName, List<ScimUser.Ref> members,
                        Meta meta) {
}
