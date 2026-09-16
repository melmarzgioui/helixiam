import React from "react";
import { Page, PageHeader, PageBody, Section } from "../components/Page";
import { Button } from "../components/Button";
import { Toast, ToastTone } from "../components/Toast";
import { Spinner } from "../components/Spinner";
import { Badge } from "../components/Badge";
import { RowMenu } from "../components/RowMenu";
import { Select } from "../components/FormField";
import { ScopeApi, ClaimApi, ScopeDetail, Claim } from "../api/scopes";
import { useT } from "../i18n/LocaleContext";

export interface ScopeDetailPageProps {
  api: ScopeApi;
  claimApi: ClaimApi;
  realmId: string;
  scopeId: string;
  onBack: () => void;
}

interface Note { tone: ToastTone; title: string; message?: string; }

/** E8.5: a single client scope — see its claims and add/remove claims from the catalogue. */
export function ScopeDetailPage({ api, claimApi, realmId, scopeId, onBack }: ScopeDetailPageProps) {
  const { t } = useT();
  const [scope, setScope] = React.useState<ScopeDetail | null>(null);
  const [catalogue, setCatalogue] = React.useState<Claim[]>([]);
  const [addClaimId, setAddClaimId] = React.useState("");
  const [note, setNote] = React.useState<Note | null>(null);
  const [notFound, setNotFound] = React.useState(false);

  const load = React.useCallback(() => {
    setScope(null);
    api.get(realmId, scopeId).then(setScope).catch(() => setNotFound(true));
  }, [api, realmId, scopeId]);

  React.useEffect(() => {
    load();
    claimApi.list(realmId).then(setCatalogue).catch(() => undefined);
  }, [load, claimApi, realmId]);

  const mappedIds = new Set((scope?.claims ?? []).map((c) => c.claimId));
  const available = catalogue.filter((c) => !mappedIds.has(c.claimId));

  const wrap = (p: Promise<unknown>, ok: Note) => p.then(() => { load(); setNote(ok); }).catch((e: Error) => setNote({ tone: "error", title: t("scopeDetail.actionFailed"), message: String(e.message ?? e) }));

  if (notFound) {
    return (
      <Page>
        <PageHeader
          title={t("scopeDetail.notFoundTitle")}
          description={<>{t("scopeDetail.notFoundDescBefore")} <strong>{realmId}</strong>.</>}
        />
        <PageBody>
          <Button variant="ghost" onClick={onBack}>{t("scopeDetail.backToScopes")}</Button>
        </PageBody>
      </Page>
    );
  }

  return (
    <Page>
      <button type="button" onClick={onBack} className="hx-backlink">{t("scopeDetail.backLink")}</button>

      <PageHeader
        title={scope?.name ?? "…"}
        description={scope?.description || <>{t("scopeDetail.descriptionPrefix")} <strong>{scope?.name}</strong> {t("scopeDetail.descriptionSuffix")}</>}
      />

      <PageBody>
        {scope === null ? (
          <div className="hx-loadwrap">
            <Spinner size={28} label={t("scopeDetail.loading")} />
          </div>
        ) : (
          <>
            <Section title={t("scopeDetail.mappedClaimsTitle")}>
              {scope.claims.length === 0 ? (
                <p className="hx-faint">{t("scopeDetail.noMappedClaims")}</p>
              ) : (
                <div className="hx-tablescroll">
                  <table className="hx-table">
                    <thead>
                      <tr><th>{t("scopeDetail.colClaim")}</th><th>{t("scopeDetail.colKey")}</th><th>{t("scopeDetail.colRequired")}</th><th className="hx-col-actions" aria-label="Actions" /></tr>
                    </thead>
                    <tbody>
                      {scope.claims.map((c) => (
                        <tr key={c.claimId}>
                          <td><strong>{c.label}</strong></td>
                          <td><code className="hx-conn__alias">{c.key}</code></td>
                          <td>{c.mandatory ? <Badge tone="accent">{t("scopeDetail.mandatory")}</Badge> : <Badge tone="neutral">{t("scopeDetail.optional")}</Badge>}</td>
                          <td className="hx-cell-right">
                            <RowMenu ariaLabel={`Actions for ${c.label}`} items={[{ label: t("scopeDetail.removeFromScope"), danger: true, onSelect: () => wrap(api.removeClaim(realmId, scopeId, c.claimId), { tone: "info", title: t("scopeDetail.claimRemoved"), message: t("scopeDetail.claimRemovedMsg", { label: c.label, scope: scope.name }) }) }]} />
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </Section>

            <Section
              title={t("scopeDetail.addClaimTitle")}
              description={<>{t("scopeDetail.addClaimDescBefore")} <strong>{t("scopeDetail.claimsLink")}</strong> {t("scopeDetail.addClaimDescAfter")}</>}
            >
              <div className="hx-inputrow">
                <div className="hx-toolbar__grow">
                  <Select
                    options={[{ value: "", label: available.length ? t("scopeDetail.chooseClaim") : t("scopeDetail.allMapped") }, ...available.map((c) => ({ value: c.claimId, label: `${c.label} (${c.key})` }))]}
                    value={addClaimId} onChange={setAddClaimId} aria-label={t("scopeDetail.addClaimTitle")}
                  />
                </div>
                <Button variant="primary" disabled={!addClaimId} onClick={() => {
                  const claim = available.find((c) => c.claimId === addClaimId);
                  wrap(api.addClaim(realmId, scopeId, addClaimId), { tone: "success", title: t("scopeDetail.claimAdded"), message: t("scopeDetail.claimAddedMsg", { label: claim?.label ?? "", scope: scope.name }) });
                  setAddClaimId("");
                }}>{t("scopeDetail.add")}</Button>
              </div>
            </Section>
          </>
        )}
      </PageBody>

      {note && (
        <div className="hx-toasthost">
          <Toast tone={note.tone} title={note.title} message={note.message} onDismiss={() => setNote(null)} />
        </div>
      )}
    </Page>
  );
}
