package group.mfnr.authorization.controller.admin.io;

import java.util.Locale;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Helix IAM: env-var placeholders for realm-export secrets. A secret is never written to an export file as
 * a literal — instead the export emits a stable placeholder {@code ${HELIX_<REALM>_<...>_<FIELD>}} and
 * records the env-var name in the document's {@code requiredEnv} manifest. On import the placeholder is
 * resolved from the environment ({@link MissingPolicy#LEAVE_UNSET leave unset} or {@link
 * MissingPolicy#FAIL fail fast} when a referenced var is absent). A non-placeholder literal passes through
 * unchanged, so a hand-written file may still inline a value if it really wants to.
 *
 * <p>Companion to {@link SecretMasking}, which remains the single source of truth for <em>which</em> fields
 * are secret; this class governs <em>how</em> they are represented and resolved.
 */
public final class SecretPlaceholders {

    /** What to do when an imported {@code ${VAR}} placeholder has no matching environment value. */
    public enum MissingPolicy {
        /** Treat the secret as unset (the field is left blank, as today's masked-import does). */
        LEAVE_UNSET,
        /** Abort with a {@link MissingSecretException} naming the missing variable. */
        FAIL
    }

    /** Thrown by {@link #resolve} under {@link MissingPolicy#FAIL} when a referenced env var is absent. */
    public static final class MissingSecretException extends RuntimeException {
        private final transient String variable;

        public MissingSecretException(final String variable) {
            super("required secret environment variable is not set: " + variable);
            this.variable = variable;
        }

        public String variable() {
            return variable;
        }
    }

    private static final String PREFIX = "HELIX";
    private static final Pattern PLACEHOLDER = Pattern.compile("^\\$\\{([A-Za-z0-9_]+)}$");

    private SecretPlaceholders() {
    }

    /** The env-var name for a secret field, e.g. {@code nameFor("gov","billing","secret")} ⇒ {@code HELIX_GOV_BILLING_SECRET}. */
    public static String nameFor(final String realmId, final String... parts) {
        final StringBuilder sb = new StringBuilder(PREFIX).append('_').append(sanitize(realmId));
        for (final String part : parts) {
            final String s = sanitize(part);
            if (!s.isEmpty()) {
                sb.append('_').append(s);
            }
        }
        return collapse(sb.toString());
    }

    /** The {@code ${...}} placeholder string for a secret field. */
    public static String placeholderFor(final String realmId, final String... parts) {
        return "${" + nameFor(realmId, parts) + "}";
    }

    /** The variable name iff {@code value} is exactly one {@code ${VAR}} placeholder, else {@code null}. */
    public static String referencedVar(final String value) {
        if (value == null) {
            return null;
        }
        final Matcher m = PLACEHOLDER.matcher(value.trim());
        return m.matches() ? m.group(1) : null;
    }

    /** Resolves a possibly-placeholder value against {@code env}; literals pass through; see {@link MissingPolicy}. */
    public static String resolve(final String value, final Function<String, String> env, final MissingPolicy policy) {
        if (value == null) {
            return null;
        }
        final String var = referencedVar(value);
        if (var == null) {
            return value; // literal — not a placeholder
        }
        final String resolved = env == null ? null : env.apply(var);
        if (resolved != null) {
            return resolved;
        }
        if (policy == MissingPolicy.FAIL) {
            throw new MissingSecretException(var);
        }
        return null; // LEAVE_UNSET
    }

    private static String sanitize(final String s) {
        return s == null ? "" : s.toUpperCase(Locale.ROOT).replaceAll("[^A-Z0-9]+", "_");
    }

    private static String collapse(final String s) {
        return s.replaceAll("_+", "_").replaceAll("^_|_$", "");
    }
}
