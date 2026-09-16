/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import React from "react";
import { Page, PageHeader, PageBody } from "../components/Page";
import { Card } from "../components/Card";
import { Alert } from "../components/Alert";
import { Badge } from "../components/Badge";
import { useT } from "../i18n/LocaleContext";

export interface InProgressPageProps {
  title: string;
  /** One-line description of what this section will do. */
  blurb: string;
  /** The capabilities this section will ship — shown as a checklist preview. */
  capabilities: string[];
  /** what Helix adds in this area — shown as a highlight. */
  beyond?: string;
  icon?: React.ReactNode;
}

/** A roadmap/compass glyph used when a section doesn't supply its own icon (avoids an empty icon tile). */
const DEFAULT_ICON = (
  <svg width="22" height="22" viewBox="0 0 24 24" fill="none" aria-hidden="true">
    <circle cx="12" cy="12" r="9" stroke="currentColor" strokeWidth="1.6" />
    <path d="M14.5 9.5l-1.2 4-4 1.2 1.2-4 4-1.2z" stroke="currentColor" strokeWidth="1.6" strokeLinejoin="round" />
  </svg>
);

/** Premium placeholder for a console section that's on the roadmap but not yet live. */
export function InProgressPage({ title, blurb, capabilities, beyond, icon }: InProgressPageProps) {
  const { t } = useT();
  return (
    <Page>
      <PageHeader
        title={<span className="hx-namecell">{title}<Badge tone="neutral">{t("inProgress.badge")}</Badge></span>}
        description={blurb}
      />

      <PageBody>
        <Card>
          <div className="hx-namecell">
            <span aria-hidden="true" className="hx-icontile">
              {icon ?? DEFAULT_ICON}
            </span>
            <div>
              <strong>{t("inProgress.card.title")}</strong>
              <div className="hx-help">{t("inProgress.card.description")}</div>
            </div>
          </div>

          <ul className="hx-checklist">
            {capabilities.map((c) => (
              <li key={c} className="hx-checklist__item">
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" aria-hidden="true">
                  <circle cx="12" cy="12" r="9" stroke="currentColor" strokeWidth="1.6" />
                  <path d="M8.5 12.5l2.5 2.5 4.5-5" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" />
                </svg>
                {c}
              </li>
            ))}
          </ul>
        </Card>

        {beyond && (
          <Alert tone="info" title={t("inProgress.beyond.title")}>{beyond}</Alert>
        )}
      </PageBody>
    </Page>
  );
}
