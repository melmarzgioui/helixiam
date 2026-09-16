package io.helixiam.authorization.domain;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.*;

@JsonIgnoreProperties(ignoreUnknown = true)
public class UserCredentials implements UserDetails {

    @JsonProperty
    private String userId;

    @JsonProperty
    private String username;

    @JsonProperty
    private String password;

    @JsonProperty
    private boolean accountExpired;

    @JsonProperty
    private boolean accountLocked;

    @JsonProperty
    private boolean credentialsExpired;

    @JsonProperty
    private boolean disabled;

    @JsonProperty
    private String mfaSecret;

    @JsonProperty
    private boolean mfaEnabled;

    @JsonProperty
    private Date creationDate;

    @JsonProperty
    private List<Map<String, String>> authorities = new ArrayList<>();

    @Override
    @JsonIgnore
    public Collection<GrantedAuthority> getAuthorities() {
        List<GrantedAuthority> grantedAuthorities = new ArrayList<>();

        authorities.forEach(stringStringMap -> stringStringMap.values().forEach(s -> grantedAuthorities.add(new SimpleGrantedAuthority(s))));
        return grantedAuthorities;
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return getUserId();
    }

    public String getUserId() {
        return userId;
    }

    public String getEmail() {
        return username;
    }
    @Override
    public boolean isAccountNonExpired() {
        return !accountExpired;
    }

    @Override
    public boolean isAccountNonLocked() {
        return !accountLocked;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return !credentialsExpired;
    }

    @Override
    public boolean isEnabled() {
        return !disabled;
    }

    public Date getCreationDate() {
        return creationDate;
    }

    public String getMfaSecret() {
        return mfaSecret;
    }

    public boolean isMfaEnabled() {
        return mfaEnabled;
    }

    @Override
    public String toString() {
        return "UserCredentials{" +
                "userId='" + userId + '\'' +
                ", username='" + username + '\'' +
                ", password='" + password + '\'' +
                ", accountExpired=" + accountExpired +
                ", accountLocked=" + accountLocked +
                ", credentialsExpired=" + credentialsExpired +
                ", disabled=" + disabled +
                ", authorities=" + authorities +
                '}';
    }
}
