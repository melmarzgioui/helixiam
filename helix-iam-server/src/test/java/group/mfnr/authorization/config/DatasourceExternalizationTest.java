package group.mfnr.authorization.config;

import org.junit.jupiter.api.Test;
import org.springframework.core.env.MapPropertySource;
import org.springframework.core.env.PropertiesPropertySource;
import org.springframework.core.env.StandardEnvironment;
import org.springframework.core.io.ClassPathResource;

import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Helix IAM PROD-1 (config externalization): the server's datasource connection coordinates must be
 * env-driven so it runs standalone, not only inside the KubeDNA e2e cluster. This pins the
 * placeholder contract in {@code application.properties}: with no environment, the datasource URL
 * and username fall back to the in-cluster KubeDNA defaults (so the existing deployment is
 * unchanged); with {@code DB_HOST}/{@code DB_NAME}/{@code DB_USERNAME} set, those flow through into
 * the resolved values (so a standalone install can point at any Postgres).
 * (The original assertions on {@code spring.rabbitmq.virtual-host}/{@code RABBITMQ_VHOST} were
 * dropped in the strip-RabbitMQ migration — helix-iam-server has no broker/AMQP config.)
 */
class DatasourceExternalizationTest {

    /** Loads application.properties and resolves placeholders against the given env overrides. */
    private StandardEnvironment envWith(final Map<String, Object> overrides) throws Exception {
        final Properties props = new Properties();
        try (var in = new ClassPathResource("application.properties").getInputStream()) {
            props.load(in);
        }
        final StandardEnvironment env = new StandardEnvironment();
        env.getPropertySources().addFirst(new MapPropertySource("env-overrides", overrides));
        env.getPropertySources().addLast(new PropertiesPropertySource("app", props));
        return env;
    }

    @Test
    void fallsBackToKubeDnaDefaultsWhenNoEnvSet() throws Exception {
        final var env = envWith(new HashMap<>());

        assertThat(env.resolveRequiredPlaceholders(env.getProperty("spring.datasource.url")))
                .isEqualTo("jdbc:postgresql://kubedna-rw.project-kubedna:5432/kubeiam");
        assertThat(env.resolveRequiredPlaceholders(env.getProperty("spring.readonly.datasource.url")))
                .isEqualTo("jdbc:postgresql://kubedna-ro.project-kubedna:5432/kubeiam");
        assertThat(env.resolveRequiredPlaceholders(env.getProperty("spring.datasource.username")))
                .isEqualTo("kubeiam");
    }

    @Test
    void honoursStandaloneEnvOverrides() throws Exception {
        final var env = envWith(Map.of(
                "DB_HOST", "pg.acme.internal",
                "DB_PORT", "6432",
                "DB_NAME", "helix",
                "DB_USERNAME", "helix_app"));

        assertThat(env.resolveRequiredPlaceholders(env.getProperty("spring.datasource.url")))
                .isEqualTo("jdbc:postgresql://pg.acme.internal:6432/helix");
        // No DB_RO_HOST → read-only host falls back to DB_HOST (single-Postgres standalone install).
        assertThat(env.resolveRequiredPlaceholders(env.getProperty("spring.readonly.datasource.url")))
                .isEqualTo("jdbc:postgresql://pg.acme.internal:6432/helix");
        assertThat(env.resolveRequiredPlaceholders(env.getProperty("spring.datasource.username")))
                .isEqualTo("helix_app");
    }

    @Test
    void separateReadOnlyHostIsHonouredWhenProvided() throws Exception {
        final var env = envWith(Map.of("DB_HOST", "primary.db", "DB_RO_HOST", "replica.db"));

        assertThat(env.resolveRequiredPlaceholders(env.getProperty("spring.datasource.url")))
                .isEqualTo("jdbc:postgresql://primary.db:5432/kubeiam");
        assertThat(env.resolveRequiredPlaceholders(env.getProperty("spring.readonly.datasource.url")))
                .isEqualTo("jdbc:postgresql://replica.db:5432/kubeiam");
    }
}
