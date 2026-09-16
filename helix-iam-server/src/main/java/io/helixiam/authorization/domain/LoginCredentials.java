/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.domain;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotNull;

@JsonIgnoreProperties(ignoreUnknown = true)
public class LoginCredentials {
    @JsonProperty
    private String username;

    @JsonProperty
    private String password;

    @NotNull
    private String passwordTest = null;

    public LoginCredentials() {
    }

    /**
     * Folded from the publisher's former {@code record LoginCredentials(String username, String password)}:
     * the web front's {@code AuthenticationProvider} constructs credentials positionally
     * ({@code new LoginCredentials(username, password)}). The subscriber-side class shape (with the
     * username-lowercasing {@code getUsername()}) is otherwise preserved.
     */
    public LoginCredentials(final String username, final String password) {
        this.username = username;
        this.password = password;
    }

    public String getUsername() {
        if(username == null) {
            return null;
        }
        return username.toLowerCase();
    }

    public String getPassword() {
        return password;
    }


    @Override
    public String toString() {
        return "LoginCredentials{username='" + username + "'}";
    }
}
