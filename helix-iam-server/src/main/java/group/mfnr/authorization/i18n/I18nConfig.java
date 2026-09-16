package group.mfnr.authorization.i18n;

import java.util.List;
import java.util.Locale;

import org.springframework.context.MessageSource;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.support.ReloadableResourceBundleMessageSource;
import org.springframework.web.servlet.LocaleResolver;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import org.springframework.web.servlet.i18n.CookieLocaleResolver;
import org.springframework.web.servlet.i18n.LocaleChangeInterceptor;

/**
 * Helix IAM — i18n / localization for the user-facing Thymeleaf templates (login, register, reset,
 * OTP / flow forms, MFA, account chrome).
 *
 * <p>Externalized strings live in {@code messages.properties} (en, default) and
 * {@code messages_nl.properties} (nl-NL). Templates reference them via Thymeleaf's {@code #{key}}.
 *
 * <p>Locale is resolved, in priority order, by:
 * <ol>
 *   <li>an explicit {@code ?lang=} request parameter (handled by {@link LocaleChangeInterceptor},
 *       which also writes it to the locale cookie so the choice persists);</li>
 *   <li>the {@code HELIX_LOCALE} cookie (set by a prior {@code ?lang=} switch — see
 *       {@link CookieLocaleResolver});</li>
 *   <li>the {@code Accept-Language} request header — see {@link AcceptHeaderCookieLocaleResolver};</li>
 *   <li>the platform default ({@code en}).</li>
 * </ol>
 *
 * <p>Only English and Dutch are advertised as supported; an {@code Accept-Language} of e.g. {@code fr}
 * falls back to {@code en} rather than rendering raw keys.
 *
 * <p>NOTE: this is a {@link WebMvcConfigurer} with a single (default) constructor, so it is exempt from
 * the multi-constructor {@code @Autowired} bean trap.
 */
@Configuration
public class I18nConfig implements WebMvcConfigurer {

    /** Cookie name for the persisted UI language. */
    public static final String LOCALE_COOKIE = "HELIX_LOCALE";

    /** Request parameter that switches + persists the language (e.g. {@code /login?lang=nl}). */
    public static final String LANG_PARAM = "lang";

    /** Languages this IAM advertises; anything else degrades to the first (default) entry. */
    public static final List<Locale> SUPPORTED = List.of(Locale.ENGLISH, Locale.forLanguageTag("nl"));

    @Bean
    public MessageSource messageSource() {
        final ReloadableResourceBundleMessageSource source = new ReloadableResourceBundleMessageSource();
        source.setBasename("classpath:messages");
        source.setDefaultEncoding("UTF-8");
        // Missing key -> render the key itself rather than throwing (defensive; en should be complete).
        source.setUseCodeAsDefaultMessage(true);
        // Fall back to the default bundle (en) when a key is absent from messages_nl.properties.
        source.setFallbackToSystemLocale(false);
        return source;
    }

    /**
     * Cookie-backed resolver seeded from {@code Accept-Language}; restricts the negotiated locale to
     * {@link #SUPPORTED} (default {@code en}).
     */
    @Bean
    public LocaleResolver localeResolver() {
        // Accept-Language negotiation (the no-cookie fallback) and the en degrade live inside the
        // resolver itself via its defaultLocaleFunction — see AcceptHeaderCookieLocaleResolver.
        final AcceptHeaderCookieLocaleResolver resolver = new AcceptHeaderCookieLocaleResolver();
        resolver.setCookiePath("/");
        return resolver;
    }

    /** Reads {@code ?lang=} and writes it to the locale cookie. */
    @Bean
    public LocaleChangeInterceptor localeChangeInterceptor() {
        final LocaleChangeInterceptor interceptor = new LocaleChangeInterceptor();
        interceptor.setParamName(LANG_PARAM);
        // Ignore an invalid ?lang= rather than 500-ing the login page.
        interceptor.setIgnoreInvalidLocale(true);
        return interceptor;
    }

    @Override
    public void addInterceptors(final InterceptorRegistry registry) {
        registry.addInterceptor(localeChangeInterceptor());
    }
}
