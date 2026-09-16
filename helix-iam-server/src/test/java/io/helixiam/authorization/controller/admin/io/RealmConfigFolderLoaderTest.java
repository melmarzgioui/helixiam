package io.helixiam.authorization.controller.admin.io;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.ArgumentCaptor;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * Helix IAM: the drop-in folder loader parses each {@code *.json}/{@code *.yaml} realm-config file, derives
 * the realm id from the file name, and applies it through the import service with the configured options.
 */
class RealmConfigFolderLoaderTest {

    @TempDir
    Path dir;

    private RealmImportService importService;

    @BeforeEach
    void setUp() {
        importService = mock(RealmImportService.class);
        when(importService.importInto(any(), any(), any()))
                .thenReturn(new RealmImportResult("x", Map.of(), null));
    }

    @Test
    void appliesJsonAndYaml_withRealmIdFromFileName_sortedByName() throws Exception {
        Files.writeString(dir.resolve("gov.json"), "{\"clients\":[{\"clientId\":\"web\"}]}");
        Files.writeString(dir.resolve("partner.yaml"), "clients:\n  - clientId: api\n");

        new RealmConfigFolderLoader(importService, dir.toString(), "skip", false).run(null);

        final ArgumentCaptor<String> realm = ArgumentCaptor.forClass(String.class);
        final ArgumentCaptor<RealmExportDocument> doc = ArgumentCaptor.forClass(RealmExportDocument.class);
        verify(importService, times(2)).importInto(realm.capture(), doc.capture(), any());
        assertThat(realm.getAllValues()).containsExactly("gov", "partner"); // sorted by file name
        assertThat(doc.getAllValues().get(0).clients()).hasSize(1);
        assertThat(doc.getAllValues().get(1).clients().get(0).clientId()).isEqualTo("api");
    }

    @Test
    void absentFolderIsANoOp() {
        new RealmConfigFolderLoader(importService, dir.resolve("does-not-exist").toString(), "skip", false)
                .run(null);
        verifyNoInteractions(importService);
    }

    @Test
    void honoursTheConfiguredConflictMode() throws Exception {
        Files.writeString(dir.resolve("gov.json"), "{}");

        new RealmConfigFolderLoader(importService, dir.toString(), "overwrite", false).run(null);

        final ArgumentCaptor<ImportOptions> opts = ArgumentCaptor.forClass(ImportOptions.class);
        verify(importService).importInto(eq("gov"), any(), opts.capture());
        assertThat(opts.getValue().onConflict()).isEqualTo(ImportOptions.OnConflict.OVERWRITE);
    }

    @Test
    void requireEnvTrueSelectsFailPolicy() throws Exception {
        Files.writeString(dir.resolve("gov.json"), "{}");

        new RealmConfigFolderLoader(importService, dir.toString(), "skip", true).run(null);

        final ArgumentCaptor<ImportOptions> opts = ArgumentCaptor.forClass(ImportOptions.class);
        verify(importService).importInto(eq("gov"), any(), opts.capture());
        assertThat(opts.getValue().missingSecretPolicy()).isEqualTo(SecretPlaceholders.MissingPolicy.FAIL);
    }
}
