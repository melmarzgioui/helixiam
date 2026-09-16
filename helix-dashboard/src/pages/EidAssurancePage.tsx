/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { ConnectionsPage } from "./ConnectionsPage";
import { Section } from "../components/Page";
import { IdentityProviderApi } from "../api/client";
import { useT } from "../i18n/LocaleContext";

export interface EidAssurancePageProps {
  api: IdentityProviderApi;
  realmId: string;
}

/** The level-of-assurance ladder per scheme — mirrors the backend `EidLevelOfAssurance` mapping. */
const LOA_SCHEMES: { scheme: string; tone: string; levels: { label: string; urn: string; rung: number }[] }[] = [
  {
    scheme: "eIDAS", tone: "#1f6feb", levels: [
      { label: "Low", urn: "http://eidas.europa.eu/LoA/low", rung: 1 },
      { label: "Substantial", urn: "http://eidas.europa.eu/LoA/substantial", rung: 2 },
      { label: "High", urn: "http://eidas.europa.eu/LoA/high", rung: 3 },
    ],
  },
  {
    scheme: "DigiD", tone: "#cf3e00", levels: [
      { label: "Basis (Low)", urn: "urn:nl-eid-gdi:1.0:LoA:Low", rung: 1 },
      { label: "Midden", urn: "urn:nl-eid-gdi:1.0:LoA:Midden", rung: 2 },
      { label: "Substantieel", urn: "urn:nl-eid-gdi:1.0:LoA:Substantial", rung: 3 },
      { label: "Hoog", urn: "urn:nl-eid-gdi:1.0:LoA:High", rung: 4 },
    ],
  },
  {
    scheme: "eHerkenning", tone: "#5b2a86", levels: [
      { label: "LoA2", urn: "urn:etoegang:core:assurance-class:loa2", rung: 2 },
      { label: "LoA2+", urn: "urn:etoegang:core:assurance-class:loa2plus", rung: 2 },
      { label: "LoA3", urn: "urn:etoegang:core:assurance-class:loa3", rung: 3 },
      { label: "LoA4", urn: "urn:etoegang:core:assurance-class:loa4", rung: 4 },
    ],
  },
];

/**
 * eID & assurance: the EU/NL electronic-identity schemes (DigiD, eHerkenning, eIDAS). These are identity
 * providers of the corresponding protocol, managed through the same wizard + admin API, plus a reference of
 * the level-of-assurance ladder each scheme exposes (set the minimum LoA per provider in its config).
 */
export function EidAssurancePage({ api, realmId }: EidAssurancePageProps) {
  const { t } = useT();

  const legend = (
    <div className="hx-mb-4">
      <Section
        title={t("eid.sectionLoaTitle")}
        description={t("eid.sectionLoaDesc")}
        layout="cols"
      >
        {LOA_SCHEMES.map((s) => (
          <div className="hx-card" key={s.scheme}>
            <table className="hx-table">
              <thead>
                {/* Dynamic per-scheme accent colour — the DS-tolerated dynamic-value exception. */}
                <tr><th colSpan={2} className="hx-scheme-th" style={{ ["--tone" as never]: s.tone }}>{s.scheme}</th></tr>
              </thead>
              <tbody>
                {s.levels.map((l) => (
                  <tr key={l.urn}>
                    <td><span className="hx-faint">{l.rung}</span> {l.label}</td>
                    <td className="hx-cell-right hx-mono hx-faint">{l.urn.split(":").pop()?.split("/").pop()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ))}
      </Section>
    </div>
  );

  return (
    <ConnectionsPage
      api={api}
      realmId={realmId}
      title={t("eid.title")}
      subtitle={<>{t("eid.subtitlePrefix")} <strong>{realmId}</strong> {t("eid.subtitleSuffix")}</>}
      addLabel={t("eid.addLabel")}
      protocols={["digid", "eherkenning", "eidas"]}
      aboveContent={legend}
      emptyTitle={t("eid.emptyTitle")}
      emptyMessage={t("eid.emptyMessage")}
    />
  );
}
