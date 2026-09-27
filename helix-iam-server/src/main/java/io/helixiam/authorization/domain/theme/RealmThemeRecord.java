/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.domain.theme;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.time.Instant;

/**
 * A realm's stored theme layer ({@code realm_theme}): the canonical JSON of an
 * {@link io.helixiam.authorization.theme.Theme} that passed validation. Never raw CSS apart from the validated
 * {@code customCss} escape hatch inside it.
 */
@Entity
@Table(name = "realm_theme")
public class RealmThemeRecord {

    @Id
    @Column(name = "realm_id")
    private String realmId;

    @Column(name = "theme_json", nullable = false, columnDefinition = "text")
    private String themeJson;

    @Column(name = "updated_at")
    private Instant updatedAt;

    /** The file theme (spec §5) this realm uses as its base layer; null for none. */
    @Column(name = "theme_name")
    private String themeName;

    protected RealmThemeRecord() {
    }

    public RealmThemeRecord(final String realmId, final String themeJson) {
        this.realmId = realmId;
        this.themeJson = themeJson;
        this.updatedAt = Instant.now();
    }

    public String getRealmId() {
        return realmId;
    }

    public String getThemeJson() {
        return themeJson;
    }

    public void setThemeJson(final String themeJson) {
        this.themeJson = themeJson;
        this.updatedAt = Instant.now();
    }

    public String getThemeName() {
        return themeName;
    }

    public void setThemeName(final String themeName) {
        this.themeName = themeName;
        this.updatedAt = Instant.now();
    }

    public Instant getUpdatedAt() {
        return updatedAt;
    }
}
