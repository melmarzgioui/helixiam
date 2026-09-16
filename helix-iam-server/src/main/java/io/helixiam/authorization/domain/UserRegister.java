/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.domain;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

@JsonIgnoreProperties(ignoreUnknown = true)
public class UserRegister {

  private final java.util.Map<String, String> attributes = new java.util.HashMap<>();

  private String firstName;
  private String lastName;
  private String username;
  private String password;
  private String email;

  private String repeatPassword;
  private boolean emailVerified = false;

  private String mobilePhone;
  private boolean mobilePhoneVerified = false;

  private String mfaSecret;

  private String name;

  public String getMfaSecret() {
    return mfaSecret;
  }

  public void setMfaSecret(String mfaSecret) {
    this.mfaSecret = mfaSecret;
  }

  public String getFirstName() {
    return firstName;
  }

  public void setFirstName(final String firstName) {
    this.firstName = firstName;
  }

  public String getLastName() {
    return lastName;
  }

  public void setLastName(final String lastName) {
    this.lastName = lastName;
  }

  public String getUsername() {
    return username;
  }

  public void setUsername(final String username) {
    this.username = username;
  }

  public String getPassword() {
    return password;
  }

  public void setPassword(final String password) {
    this.password = password;
  }

  public String getRepeatPassword() {
    return repeatPassword;
  }

  public void setRepeatPassword(final String repeatPassword) {
    this.repeatPassword = repeatPassword;
  }

  public String getMobilePhone() {
    return mobilePhone;
  }

  public void setMobilePhone(final String mobilePhone) {
    this.mobilePhone = mobilePhone;
  }

  public String getEmail() {
    return email;
  }

  public void setEmail(final String email) {
    this.email = email;
  }

  @com.fasterxml.jackson.annotation.JsonAnyGetter
  public java.util.Map<String, String> getAttributes() {
    return attributes;
  }

  /** Collects a dynamic registration-claim value (rendered from the realm's claim catalogue). */
  public void putAttribute(final String key, final String value) {
    if (key != null && !key.isBlank()) {
      attributes.put(key, value);
    }
  }
}
