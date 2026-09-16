package io.helixiam.authorization.security.audit;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.List;

/**
 * Helix IAM E8.5-S4 (Events): audit/SIEM delivery configuration, sourced from the config file / env
 * (12-factor — secrets live here, never in a runtime-editable UI). Bound from {@code helix.audit.*}
 * (e.g. {@code HELIX_AUDIT_ENABLED}, {@code HELIX_AUDIT_HTTP_URL}, {@code HELIX_AUDIT_HTTP_AUTHHEADER}).
 * Global (one config per deployment). Audit JSON always goes to stdout; when {@link Http#url} is set the
 * event is also POSTed to that SIEM webhook.
 */
@ConfigurationProperties(prefix = "helix.audit")
public class HelixAuditProperties {

    /** Master switch for audit emission. */
    private boolean enabled = true;

    /** Which event categories to emit/forward ({@code AUTHN}, {@code ADMIN}). */
    private List<String> categories = List.of(AuditEvent.AUTHN, AuditEvent.ADMIN);

    private final Http http = new Http();

    /** True when the category is enabled for shipping. */
    public boolean ships(final String category) {
        return enabled && categories != null && categories.contains(category);
    }

    /** True when a SIEM HTTP webhook target is configured. */
    public boolean httpConfigured() {
        return http.url != null && !http.url.isBlank();
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(final boolean enabled) {
        this.enabled = enabled;
    }

    public List<String> getCategories() {
        return categories;
    }

    public void setCategories(final List<String> categories) {
        this.categories = categories;
    }

    public Http getHttp() {
        return http;
    }

    /** SIEM HTTP webhook target. */
    public static class Http {
        /** Webhook URL; when blank, HTTP push is off (stdout only). */
        private String url;
        /** Value for an Authorization-style header sent with each POST (secret — never exposed). */
        private String authHeader;
        /** Per-request timeout in milliseconds. */
        private int timeoutMs = 2000;

        public String getUrl() {
            return url;
        }

        public void setUrl(final String url) {
            this.url = url;
        }

        public String getAuthHeader() {
            return authHeader;
        }

        public void setAuthHeader(final String authHeader) {
            this.authHeader = authHeader;
        }

        public boolean authConfigured() {
            return authHeader != null && !authHeader.isBlank();
        }

        public int getTimeoutMs() {
            return timeoutMs;
        }

        public void setTimeoutMs(final int timeoutMs) {
            this.timeoutMs = timeoutMs;
        }
    }
}
