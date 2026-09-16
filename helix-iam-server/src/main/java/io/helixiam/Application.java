/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.data.redis.RedisRepositoriesAutoConfiguration;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.boot.autoconfigure.security.servlet.UserDetailsServiceAutoConfiguration;
import org.springframework.boot.web.servlet.ServletComponentScan;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.springframework.security.core.context.SecurityContextHolder;

/**
 * Merged entry point (strip-RabbitMQ migration). Was the subscriber's own
 * {@code @SpringBootApplication} (Task 2), now also root for the vendored {@code io.helixiam.*}
 * infra (Task 1) and the folded OAuth2/OIDC/SAML web front (Task 3, formerly the publisher).
 *
 * <p>{@code scanBasePackages} is explicit at the {@code io.helixiam} root so the single scan covers
 * both the business code ({@code io.helixiam.authorization.*}) and the vendored infra
 * ({@code io.helixiam.{common,notification,persistence,security}}). For the same reason
 * {@code @EntityScan} and {@code @EnableJpaRepositories} name that root: Boot's JPA auto-configuration
 * otherwise scans only the {@code @AutoConfigurationPackage} (this class's package) and would miss the
 * vendored {@code io.helixiam.notification} entity/repository ({@code NotificationCode} / {@code NotificationCodeRepository}).
 *
 * <p>Folded from the publisher's own {@code @SpringBootApplication}:
 * {@code exclude = UserDetailsServiceAutoConfiguration} (the app supplies its own
 * {@code AuthenticationProvider}, not Boot's default user-details service), {@code @ServletComponentScan}
 * (the web front registers filters/servlets via {@code @WebFilter}/{@code @WebServlet}), and the
 * {@code MODE_INHERITABLETHREADLOCAL} security-context strategy (so the security context propagates to
 * child threads).
 *
 * <p>Task 5: {@code RedisRepositoriesAutoConfiguration} is excluded — Redis is kept for HTTP session
 * and the optional token store, but the app declares no Spring Data Redis ({@code @RedisHash})
 * repositories, so its scanning would only churn over the JPA repositories in a pointless multi-store
 * assignment. Excluding it removes that noise; the {@code RedisConnectionFactory}/{@code RedisTemplate}
 * beans (used by session and the opt-in Redis stores) are unaffected.
 */
@SpringBootApplication(scanBasePackages = "io.helixiam",
        exclude = {UserDetailsServiceAutoConfiguration.class, RedisRepositoriesAutoConfiguration.class})
@ServletComponentScan
@EntityScan(basePackages = "io.helixiam")
@EnableJpaRepositories(basePackages = "io.helixiam")
@EnableJpaAuditing
public class Application {

    public static void main(final String[] args) {
        SecurityContextHolder.setStrategyName(SecurityContextHolder.MODE_INHERITABLETHREADLOCAL);
        SpringApplication.run(Application.class, args);
    }
}
