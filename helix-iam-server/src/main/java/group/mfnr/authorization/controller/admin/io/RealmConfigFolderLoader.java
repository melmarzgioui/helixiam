package group.mfnr.authorization.controller.admin.io;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;

import java.io.File;
import java.util.Arrays;
import java.util.Comparator;

/**
 * Helix IAM: config-as-code drop-in folder. On startup the publisher scans a mounted directory
 * ({@code helix.realms.location}, default {@code /realms}) for {@code *.json} / {@code *.yaml} / {@code *.yml}
 * realm-config files and applies each through the existing {@link RealmImportService}. The realm id is taken
 * from the file name (so {@code gov.json} configures realm {@code gov}), {@code ${ENV_VAR}} secret
 * placeholders are resolved from the environment, and the apply is idempotent.
 *
 * <p>The default conflict mode is {@code skip} ({@code helix.realms.on-conflict}) so a restart never clobbers
 * a live realm — set it to {@code overwrite} to reconcile. {@code helix.realms.require-env=true} fails a file
 * whose secret env var is missing (default leaves the secret unset). Mirrors the {@code ServiceProviderService}
 * mounted-file pattern and the {@code RealmBootstrap} runner: non-fatal — a bad file is logged and skipped,
 * boot continues.
 */
@Component
public class RealmConfigFolderLoader implements ApplicationRunner {

    private static final Logger LOG = LogManager.getLogger(RealmConfigFolderLoader.class);

    private final RealmImportService importService;
    private final String location;
    private final String onConflict;
    private final boolean requireEnv;
    private final ObjectMapper json = new ObjectMapper();
    private final ObjectMapper yaml = new ObjectMapper(new YAMLFactory());

    @Autowired
    public RealmConfigFolderLoader(final RealmImportService importService,
                                   @Value("${helix.realms.location:/realms}") final String location,
                                   @Value("${helix.realms.on-conflict:skip}") final String onConflict,
                                   @Value("${helix.realms.require-env:false}") final boolean requireEnv) {
        this.importService = importService;
        this.location = location;
        this.onConflict = onConflict;
        this.requireEnv = requireEnv;
    }

    @Override
    public void run(final ApplicationArguments args) {
        if (location == null || location.isBlank()) {
            return;
        }
        final File dir = new File(location);
        if (!dir.isDirectory()) {
            LOG.info("Helix realm-config folder '{}' not present — skipping config-as-code load", location);
            return;
        }
        final File[] files = dir.listFiles((d, name) -> isConfigFile(name));
        if (files == null || files.length == 0) {
            return;
        }
        Arrays.sort(files, Comparator.comparing(File::getName));
        final ImportOptions options = new ImportOptions(ImportOptions.conflictOf(onConflict),
                requireEnv ? SecretPlaceholders.MissingPolicy.FAIL : SecretPlaceholders.MissingPolicy.LEAVE_UNSET);

        for (final File file : files) {
            applyFile(file, options);
        }
    }

    private void applyFile(final File file, final ImportOptions options) {
        final String realmId = stripExtension(file.getName());
        try {
            final ObjectMapper mapper = file.getName().toLowerCase().endsWith(".json") ? json : yaml;
            final RealmExportDocument doc = mapper.readValue(file, RealmExportDocument.class);
            final RealmImportResult result = importService.importInto(realmId, doc, options);
            LOG.info("Helix realm-config: applied '{}' → realm '{}' {}", file.getName(), realmId, result.slices());
            if (result.conflicts() != null && !result.conflicts().isEmpty()) {
                LOG.warn("Helix realm-config: '{}' had conflicts (on-conflict={}): {}",
                        file.getName(), onConflict, result.conflicts());
            }
        } catch (final SecretPlaceholders.MissingSecretException ex) {
            LOG.error("Helix realm-config: '{}' references unset secret env var '{}' (require-env=true) — skipped",
                    file.getName(), ex.variable());
        } catch (final Exception ex) {
            LOG.error("Helix realm-config: failed to apply '{}': {}", file.getName(), ex.toString());
        }
    }

    private static boolean isConfigFile(final String name) {
        final String n = name.toLowerCase();
        return n.endsWith(".json") || n.endsWith(".yaml") || n.endsWith(".yml");
    }

    private static String stripExtension(final String name) {
        final int dot = name.lastIndexOf('.');
        return dot > 0 ? name.substring(0, dot) : name;
    }
}
