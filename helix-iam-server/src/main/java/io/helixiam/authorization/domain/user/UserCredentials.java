/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.domain.user;

import com.fasterxml.jackson.annotation.*;
import io.helixiam.authorization.domain.user.UserRoles;
import io.helixiam.persistence.security.AttributeEncryption;
import jakarta.persistence.*;
import org.hibernate.annotations.ColumnTransformer;
import org.hibernate.annotations.CreationTimestamp;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.*;

@Entity
@Table(name = "user_credentials")
@JsonIgnoreProperties(ignoreUnknown = true)
public class UserCredentials implements UserDetails {
    private static final long serialVersionUID = 8418228280517772396L;


    @JsonProperty
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @ColumnTransformer(write = "LOWER(?)")
    @Column(name = "user_id", updatable = false)
    private String userId;

    // Helix IAM: usernames are free-form — not forced to be emails — so admin/service
    // accounts (e.g. the bootstrap `admin`) and non-email usernames are valid. Email is a separate
    // product concern enforced by the registration flow, not a blanket entity constraint.
    @JsonProperty
    @ColumnTransformer(write = "LOWER(?)")
    @Column(name = "username")
    private String username;

    // Helix IAM: optional email address. Stored lowercase (like username) so an account can be resolved
    // by either identifier at login. Nullable + unique — many accounts (service/admin) have no email.
    @JsonProperty
    @ColumnTransformer(write = "LOWER(?)")
    @Column(name = "email")
    private String email;

    @JsonProperty
    @Column(name = "password")
    private String password;

    @JsonProperty
    @Transient
    private String repeatPassword;

    @JsonProperty
    @Column(name = "password_salt_value")
    private String passwordSaltValue;

    @JsonProperty
    @Transient
    private boolean accountExpired;

    @JsonProperty
    @Column(name = "account_locked")
    private boolean accountLocked;

    @JsonProperty
    @Transient
    private boolean credentialsExpired;

    @JsonProperty
    @Column(name = "account_disabled")
    private boolean disabled;

    @JsonProperty
    @Column(name = "mfa_enabled")
    private boolean mfaEnabled;

    @JsonProperty
    @Convert(converter = AttributeEncryption.class)
    @Column(name = "mfa_secret")
    private String mfaSecret;

    // B1: required actions the user must complete at next login (CSV, e.g.
    // "UPDATE_PASSWORD,VERIFY_EMAIL"). Blank/null = none.
    @JsonProperty
    @Column(name = "required_actions")
    private String requiredActions;

    @CreationTimestamp
    @JsonProperty
    @Column(name = "creation_date", updatable = false)
    private Date creationDate;

    @LastModifiedDate
    @Column(name = "modify_date")
    private Date modifyDate;


    @JsonProperty
    @OneToMany(fetch = FetchType.EAGER)
    @JoinTable(
            name = "user_in_role",
            joinColumns = {@JoinColumn(name = "user_id")},
            inverseJoinColumns = {@JoinColumn(name = "role_id")}
    )
    private Set<UserRoles> authorities = new HashSet<>();


    @Override
    public Collection<GrantedAuthority> getAuthorities() {
        final Set<GrantedAuthority> processed = new HashSet<>();

        authorities.forEach(role -> processed.add(role::getTenantRoleName));

        return processed;
    }

    public Set<UserRoles> getUserRoles() {
        return authorities;
    }

    public String getUserId() {
        return userId;
    }

    public void setPassword(final String password) {
        this.password = password;
    }

    public void setPasswordSaltValue(final String passwordSaltValue) {
        this.passwordSaltValue = passwordSaltValue;
    }

    public String getPassword() {
        return password;
    }

    @Override
    @JsonIgnore
    public String getUsername() {
        return username;
    }

    @Override
    @JsonIgnore
    public boolean isAccountNonExpired() {
        return false;
    }

    @Override
    @JsonIgnore
    public boolean isAccountNonLocked() {
        return accountLocked;
    }

    public void setAccountLocked(final boolean accountLocked) {
        this.accountLocked = accountLocked;
    }

    @Override
    @JsonIgnore
    public boolean isCredentialsNonExpired() {
        return false;
    }

    @JsonIgnore
    @Override
    public boolean isEnabled() {
        return true;
    }

    public String getPasswordSaltValue() {
        return passwordSaltValue;
    }



    @JsonAnyGetter
    @JsonAnySetter
    @ElementCollection(fetch = FetchType.EAGER)
    @MapKeyColumn(name="name")
    @Column(name="value")
    @CollectionTable(name="user_profile", joinColumns=@JoinColumn(name="user_id"))
    private Map<String, String> userAttributes = new HashMap<>();

    public Map<String, String> getUserAttributes() {
        return userAttributes;
    }

    @Override
    public String toString() {
        return "UserCredentials{" +
                "userId='" + userId + '\'' +
                ", username='" + username + '\'' +
                ", accountExpired=" + accountExpired +
                ", accountLocked=" + accountLocked +
                ", credentialsExpired=" + credentialsExpired +
                ", disabled=" + disabled +
                ", authorities=" + authorities +
                '}';
    }

    public void setUsername(final String username) {
        this.username = username;
    }

    /** The account's email address, or {@code null} if none is set. */
    public String getEmail() {
        return email;
    }

    public void setEmail(final String email) {
        this.email = email;
    }

    // --- Admin (E8.5) accessors: direct field access for the Users admin API ---

    public void setUserId(final String userId) {
        this.userId = userId;
    }

    /** Whether the account is administratively disabled (distinct from the lock flag). */
    public boolean isDisabled() {
        return disabled;
    }

    public void setDisabled(final boolean disabled) {
        this.disabled = disabled;
    }

    /** Raw value of the account-locked flag (the {@link #isAccountNonLocked()} view is legacy). */
    public boolean isLocked() {
        return accountLocked;
    }

    public boolean isMfaEnabled() {
        return mfaEnabled;
    }

    public void setMfaEnabled(final boolean mfaEnabled) {
        this.mfaEnabled = mfaEnabled;
    }

    public String getMfaSecret() {
        return mfaSecret;
    }

    public void setMfaSecret(final String mfaSecret) {
        this.mfaSecret = mfaSecret;
    }

    public String getRequiredActions() {
        return requiredActions;
    }

    public void setRequiredActions(final String requiredActions) {
        this.requiredActions = requiredActions;
    }

    public Date getCreationDate() {
        return creationDate;
    }
}
