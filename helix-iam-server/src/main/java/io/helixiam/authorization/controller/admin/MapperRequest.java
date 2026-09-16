package io.helixiam.authorization.controller.admin;

/**
 * Helix IAM (Wave 3): request body for creating / updating a client's protocol mapper. {@code mapperType} is
 * {@code USER_ATTRIBUTE} (maps {@code source} attribute → {@code claimName}) or {@code HARDCODED} ({@code source}
 * literal → {@code claimName}).
 */
public record MapperRequest(@jakarta.validation.constraints.NotBlank(message = "Mapper name is required.") String name,
                            @jakarta.validation.constraints.NotBlank(message = "Mapper type is required.") String mapperType,
                            String source, String claimName,
                            Boolean addToAccessToken, Boolean addToIdToken) {
}
