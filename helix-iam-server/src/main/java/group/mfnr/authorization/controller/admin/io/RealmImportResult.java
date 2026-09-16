package group.mfnr.authorization.controller.admin.io;

import com.fasterxml.jackson.annotation.JsonInclude;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Helix IAM: the per-slice outcome of a realm import. For each slice the console showed a count of how
 * many natural-key entries were {@code created}, {@code updated} (already existed → upserted), or
 * {@code skipped} (malformed, or blocked by the {@code SKIP}/{@code FAIL} conflict mode). Under
 * {@code FAIL}, every entry whose key already existed is also listed in {@code conflicts} ({@code
 * slice:key}) so the caller can surface / reject it. Returned by {@code POST /admin/realms/{realm}/import}.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record RealmImportResult(String realm, Map<String, SliceSummary> slices, List<String> conflicts) {

    /** Counts for a single slice. */
    public record SliceSummary(int created, int updated, int skipped) {
    }

    /** A mutable accumulator the import service fills while it walks the document, then freezes. */
    public static final class Builder {
        private final String realm;
        private final Map<String, int[]> counts = new LinkedHashMap<>();
        private final List<String> conflicts = new ArrayList<>();

        public Builder(final String realm) {
            this.realm = realm;
        }

        private int[] slot(final String slice) {
            return counts.computeIfAbsent(slice, k -> new int[3]);
        }

        public void created(final String slice) {
            slot(slice)[0]++;
        }

        public void updated(final String slice) {
            slot(slice)[1]++;
        }

        public void skipped(final String slice) {
            slot(slice)[2]++;
        }

        /** Records a natural-key collision (FAIL mode) as {@code slice:key}. */
        public void conflict(final String slice, final String key) {
            conflicts.add(slice + ":" + key);
        }

        public RealmImportResult build() {
            final Map<String, SliceSummary> out = new LinkedHashMap<>();
            counts.forEach((slice, c) -> out.put(slice, new SliceSummary(c[0], c[1], c[2])));
            return new RealmImportResult(realm, out, conflicts.isEmpty() ? null : List.copyOf(conflicts));
        }
    }
}
