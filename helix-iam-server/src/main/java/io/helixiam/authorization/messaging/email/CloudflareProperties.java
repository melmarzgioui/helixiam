/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.messaging.email;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;

/**
 * The global Cloudflare Email Service settings, used when {@code helix.notification.email.driver=cloudflare} (prefix
 * {@code helix.notification.cloudflare}): {@code account-id}, {@code api-token} or {@code api-token-file} (a mounted
 * secret, read at every send so a rotated token needs no restart; the file wins over the value), {@code base-url},
 * {@code connect-timeout}, {@code read-timeout} and {@code ca-bundle-file} (PEM, for a TLS-inspecting proxy).
 */
@ConfigurationProperties(prefix = "helix.notification.cloudflare")
public class CloudflareProperties {

    private String accountId;
    private String apiToken;
    private String apiTokenFile;
    private String baseUrl;
    private Duration connectTimeout;
    private Duration readTimeout;
    private String caBundleFile;

    public String getAccountId() {
        return accountId;
    }

    public void setAccountId(final String accountId) {
        this.accountId = accountId;
    }

    public String getApiToken() {
        return apiToken;
    }

    public void setApiToken(final String apiToken) {
        this.apiToken = apiToken;
    }

    public String getApiTokenFile() {
        return apiTokenFile;
    }

    public void setApiTokenFile(final String apiTokenFile) {
        this.apiTokenFile = apiTokenFile;
    }

    public String getBaseUrl() {
        return baseUrl;
    }

    public void setBaseUrl(final String baseUrl) {
        this.baseUrl = baseUrl;
    }

    public Duration getConnectTimeout() {
        return connectTimeout;
    }

    public void setConnectTimeout(final Duration connectTimeout) {
        this.connectTimeout = connectTimeout;
    }

    public Duration getReadTimeout() {
        return readTimeout;
    }

    public void setReadTimeout(final Duration readTimeout) {
        this.readTimeout = readTimeout;
    }

    public String getCaBundleFile() {
        return caBundleFile;
    }

    public void setCaBundleFile(final String caBundleFile) {
        this.caBundleFile = caBundleFile;
    }

    @Override
    public String toString() {
        return "CloudflareProperties[accountId=" + accountId + ", apiToken=" + (apiToken == null ? "unset" : "***")
                + ", apiTokenFile=" + (apiTokenFile == null ? "unset" : "set") + ", baseUrl=" + baseUrl + "]";
    }
}
