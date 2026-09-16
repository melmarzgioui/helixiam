package io.helixiam.persistence.config;

import com.zaxxer.hikari.HikariDataSource;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.util.StringUtils;

import javax.sql.DataSource;
import java.util.HashMap;
import java.util.Map;

/**
 * Vendored verbatim (package renamed only) from
 * group.mfnr.subscriber.starter.database.config.DataSourceConfiguration.
 *
 * Single-datasource fallback (unchanged from the original): when
 * {@code spring.readonly.datasource.url} is not set, both the UPDATABLE and READONLY routing
 * keys resolve to the same read-write Hikari pool, so the app starts and runs fine with just
 * {@code spring.datasource.*} configured. A separate read replica is opt-in.
 */
@Configuration
public class DataSourceConfiguration {

    @Value("${spring.datasource.url}")
    private String readWriteUrl;

    @Value("${spring.datasource.username}")
    private String readWriteUsername;

    @Value("${spring.datasource.password}")
    private String readWritePassword;

    @Value("${spring.datasource.driver-class-name}")
    private String readWriteDriver;

    @Value("${spring.readonly.datasource.url:#{null}}")
    private String readOnlyUrl;

    @Value("${spring.datasource.hikari.auto-commit:false}")
    private boolean autoCommit;
    @Bean
    public DataSource dataSource(){
        final DataSource readWriteDatasource = readWriteDataSource();

        final Map<Object, Object> targetDataSources = new HashMap<>();
        targetDataSources.put(DatabaseEnvironment.UPDATABLE, readWriteDatasource);
        if(StringUtils.hasText(readOnlyUrl)) {
            targetDataSources.put(DatabaseEnvironment.READONLY, readOnlyDataSource());
        } else {
            targetDataSources.put(DatabaseEnvironment.READONLY, readWriteDatasource);
        }

        final ReadWriteRoutingDataSource readWriteRoutingDataSource = new ReadWriteRoutingDataSource();
        readWriteRoutingDataSource.setTargetDataSources(targetDataSources);
        readWriteRoutingDataSource.setDefaultTargetDataSource(readWriteDatasource);

        return readWriteRoutingDataSource;
    }

    public DataSource readOnlyDataSource() {
        final HikariDataSource hikariDataSource = new HikariDataSource();
        hikariDataSource.setJdbcUrl(readOnlyUrl);
        hikariDataSource.setUsername(readWriteUsername);
        hikariDataSource.setPassword(readWritePassword);
        hikariDataSource.setDriverClassName(readWriteDriver);
        hikariDataSource.setAutoCommit(autoCommit);
        hikariDataSource.setMaximumPoolSize(30);

        return hikariDataSource;
    }

    public DataSource readWriteDataSource() {
        final HikariDataSource hikariDataSource = new HikariDataSource();
        hikariDataSource.setJdbcUrl(readWriteUrl);
        hikariDataSource.setUsername(readWriteUsername);
        hikariDataSource.setPassword(readWritePassword);
        hikariDataSource.setDriverClassName(readWriteDriver);
        hikariDataSource.setAutoCommit(autoCommit);

        return hikariDataSource;
    }
}
