package group.mfnr.authorization.i18n;

import java.util.Locale;

import org.springframework.lang.Nullable;
import org.springframework.web.servlet.i18n.CookieLocaleResolver;

import jakarta.servlet.http.HttpServletRequest;

/**
 * Helix IAM i18n — a {@link CookieLocaleResolver} that, when no language cookie is present, negotiates
 * the locale from the request's {@code Accept-Language} header (via the parent's
 * {@code defaultLocaleFunction} hook) instead of falling straight back to a fixed default. The result
 * is constrained to the platform's {@link I18nConfig#SUPPORTED supported languages}; any unsupported
 * request degrades to {@code en}.
 *
 * <p>Resolution order for a given request (all handled here or by the parent):
 * <ol>
 *   <li>{@code HELIX_LOCALE} cookie (set by a {@code ?lang=} switch via {@code LocaleChangeInterceptor});</li>
 *   <li>{@code Accept-Language}, restricted to the supported set;</li>
 *   <li>{@code en}.</li>
 * </ol>
 *
 * <p>Delegating cookie handling to the parent means the post-switch request attribute the
 * {@code LocaleChangeInterceptor} writes is honoured for the rest of the same request — we do not
 * re-parse cookies ourselves.
 *
 * <p>Single constructor (default) — exempt from the multi-constructor {@code @Autowired} trap.
 */
public class AcceptHeaderCookieLocaleResolver extends CookieLocaleResolver {

    public AcceptHeaderCookieLocaleResolver() {
        super(I18nConfig.LOCALE_COOKIE);
        // No cookie? Negotiate from Accept-Language, constrained to the supported set.
        setDefaultLocaleFunction(request -> supportedOrDefault(request.getLocale()));
    }

    @Override
    public Locale resolveLocale(final HttpServletRequest request) {
        // Parent applies: cookie (or the interceptor's same-request attribute) -> defaultLocaleFunction.
        // Re-clamp to the supported set so a stale/hand-set cookie like "fr" still degrades to en.
        return supportedOrDefault(super.resolveLocale(request));
    }

    /** Matches the requested locale's language against {@link I18nConfig#SUPPORTED}; else {@code en}. */
    static Locale supportedOrDefault(@Nullable final Locale requested) {
        if (requested == null || requested.getLanguage().isEmpty()) {
            return Locale.ENGLISH;
        }
        for (final Locale supported : I18nConfig.SUPPORTED) {
            if (supported.getLanguage().equals(requested.getLanguage())) {
                return supported;
            }
        }
        return Locale.ENGLISH;
    }
}
