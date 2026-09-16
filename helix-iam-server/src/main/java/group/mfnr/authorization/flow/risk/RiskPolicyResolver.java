package group.mfnr.authorization.flow.risk;

import group.mfnr.authorization.amqp.realm.RealmSettingsDto;
import group.mfnr.authorization.security.realm.RealmSettingsResolver;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.stereotype.Component;

import java.lang.reflect.Method;

/**
 * Helix IAM (adaptive auth): resolves the per-realm {@link RiskPolicy} at login time from the
 * realm settings (via {@link RealmSettingsResolver}, which caches + degrades to defaults), so the
 * policy is read per-realm with no restart, exactly like the SSO and lockout settings.
 *
 * <p><b>Contract-safe field access.</b> The seven risk-policy fields are appended to the shared
 * {@code RealmSettingsDto} record (reported as a paste-ready delta — see the change notes). To
 * keep this module compiling and shipping independently of that shared edit, the policy fields are
 * read <i>reflectively</i> by accessor name. If the accessors are not present yet (delta not
 * applied), or the realm has not enabled risk auth, this resolver returns {@link
 * RiskPolicy#disabled()} — i.e. <b>risk auth defaults OFF and the login path is unchanged</b>.
 * Once the DTO delta is applied the reflection finds the accessors and the policy lights up with
 * no further change here.
 *
 * <p>Expected appended record components (booleans/ints):
 * {@code riskPolicyEnabled, riskMediumThreshold, riskHighThreshold,
 * riskLowAction, riskMediumAction, riskHighAction} (action fields are {@code String}).
 */
@Component
public class RiskPolicyResolver {

    private static final Logger LOG = LogManager.getLogger(RiskPolicyResolver.class);

    private final RealmSettingsResolver settingsResolver;

    public RiskPolicyResolver(final RealmSettingsResolver settingsResolver) {
        this.settingsResolver = settingsResolver;
    }

    /** The realm's risk policy; {@link RiskPolicy#disabled()} (default OFF) when unset/unavailable. */
    public RiskPolicy resolve(final String realmId) {
        try {
            final RealmSettingsDto settings = settingsResolver.get(realmId);
            if (settings == null) {
                return RiskPolicy.disabled();
            }
            return fromSettings(settings);
        } catch (final RuntimeException e) {
            LOG.warn("Risk-policy lookup failed for realm {}, treating as disabled: {}", realmId, e.getMessage());
            return RiskPolicy.disabled();
        }
    }

    /**
     * Builds a policy from the DTO via reflective accessors. Returns {@link RiskPolicy#disabled()}
     * if the accessors are absent (shared DTO delta not yet applied) or the realm has it disabled.
     */
    static RiskPolicy fromSettings(final RealmSettingsDto settings) {
        final Boolean enabled = readBoolean(settings, "riskPolicyEnabled");
        if (enabled == null) {
            // Field not present on the DTO yet (delta not applied) → feature off, login unchanged.
            return RiskPolicy.disabled();
        }
        if (!enabled) {
            return RiskPolicy.disabled();
        }
        final int medium = orDefault(readInt(settings, "riskMediumThreshold"), 40);
        final int high = orDefault(readInt(settings, "riskHighThreshold"), 70);
        final RiskAction low = RiskAction.fromString(readString(settings, "riskLowAction"));
        final RiskAction med = RiskAction.fromString(readString(settings, "riskMediumAction"));
        final RiskAction hi = RiskAction.fromString(readString(settings, "riskHighAction"));
        // Guard the threshold ordering so a mis-entered policy can't invert the bands.
        final int mediumClamped = Math.max(0, Math.min(100, medium));
        final int highClamped = Math.max(mediumClamped, Math.min(100, high));
        return new RiskPolicy(true, mediumClamped, highClamped, low, med, hi);
    }

    private static int orDefault(final Integer value, final int fallback) {
        return value == null ? fallback : value;
    }

    private static Boolean readBoolean(final Object target, final String accessor) {
        final Object v = invoke(target, accessor);
        return v instanceof Boolean b ? b : null;
    }

    private static Integer readInt(final Object target, final String accessor) {
        final Object v = invoke(target, accessor);
        return v instanceof Integer i ? i : null;
    }

    private static String readString(final Object target, final String accessor) {
        final Object v = invoke(target, accessor);
        return v instanceof String s ? s : null;
    }

    private static Object invoke(final Object target, final String accessor) {
        try {
            final Method m = target.getClass().getMethod(accessor);
            return m.invoke(target);
        } catch (final ReflectiveOperationException e) {
            return null; // accessor not present yet — caller treats as disabled/default
        }
    }
}
