import React from "react";
import { Page, PageHeader, PageBody } from "../components/Page";
import { Button } from "../components/Button";
import { Modal, ConfirmDialog } from "../components/Modal";
import { Toast, ToastTone } from "../components/Toast";
import { Spinner } from "../components/Spinner";
import { Badge } from "../components/Badge";
import { LoaBadge, LoaLevel } from "../components/LoaBadge";
import { FormField, Select, Input } from "../components/FormField";
import { FlowApi, FlowExecution, FlowSummary, AuthenticatorCatalogEntry, isConditionCatalogEntry } from "../api/flows";
import { IdentityProviderApi, createHttpClient as createIdpClient } from "../api/client";
import {
  requirementMeta,
  REQUIREMENT_OPTIONS,
  toJourney,
  previewScreens,
  summarizeJourney,
  JourneyStage,
} from "./flowModel";
import { useT } from "../i18n/LocaleContext";

export interface AuthFlowPageProps {
  api: FlowApi;
  realmId: string;
  /** Source of the realm's identity providers for the idp-redirect step's alias picker (defaults to HTTP). */
  idpApi?: IdentityProviderApi;
}

/** A minimal identity-provider option for the idp-redirect step's alias picker. */
export interface IdpOption { alias: string; displayName: string; }

interface Note { tone: ToastTone; title: string; message?: string; }
type Mode = "simple" | "advanced";
const MODE_KEY = "helix.authflow.mode";
const BROWSER_ALIAS = "browser";
/** A flow alias is a short slug: lowercase letters, numbers and hyphens. */
const ALIAS_RE = /^[a-z0-9][a-z0-9-]{1,62}$/;

const newId = () =>
  (globalThis.crypto?.randomUUID?.() ?? `new-${Math.random().toString(36).slice(2)}-${Date.now()}`);

const isConditionEntry = isConditionCatalogEntry;
const loaTier = (n: number): LoaLevel => (n >= 5 ? "high" : n >= 3 ? "substantial" : "low");

function defaultFlowNameT(key: string, params?: Record<string, string | number>): string {
  if (key === "authFlow.error.noName") return "Give the flow a name.";
  if (key === "authFlow.error.invalidAlias") return "Use lowercase letters, numbers and hyphens (2–63 chars).";
  if (key === "authFlow.error.alreadyExists") return `A flow named "${params?.name ?? ""}" already exists.`;
  return key;
}

/**
 * Helix IAM — the Authentication editor, reimagined as a plain-language sign-in journey, not a raw execution table.
 * A Simple "Sign-in journey" stepper (with a live login preview) and an Advanced flow canvas,
 * both editing the SAME underlying execution tree, so the toggle never loses work.
 */
export function AuthFlowPage({ api, realmId, idpApi }: AuthFlowPageProps) {
  const { t } = useT();
  const [loaded, setLoaded] = React.useState<FlowExecution[] | null>(null);
  const [execs, setExecs] = React.useState<FlowExecution[]>([]);
  const [catalog, setCatalog] = React.useState<AuthenticatorCatalogEntry[]>([]);
  const [idps, setIdps] = React.useState<IdpOption[]>([]);
  const [builtIn, setBuiltIn] = React.useState(false);
  const [busy, setBusy] = React.useState(false);
  const [note, setNote] = React.useState<Note | null>(null);
  const [mode, setMode] = React.useState<Mode>(() => (localStorage.getItem(MODE_KEY) as Mode) || "simple");
  const [picker, setPicker] = React.useState<{ stageId: string | null; condition: boolean } | null>(null);
  const [alias, setAlias] = React.useState<string>(BROWSER_ALIAS);
  const [flows, setFlows] = React.useState<FlowSummary[]>([]);
  const [dialog, setDialog] = React.useState<"new" | "create" | "rename" | null>(null);
  const [confirmDel, setConfirmDel] = React.useState(false);

  const setModePersist = (m: Mode) => { setMode(m); localStorage.setItem(MODE_KEY, m); };

  const loadFlows = React.useCallback(() => {
    api.list(realmId).then(setFlows).catch(() => undefined);
  }, [api, realmId]);

  const reload = React.useCallback(() => {
    setLoaded(null);
    Promise.all([api.getByAlias(realmId, alias), api.catalog(realmId)])
      .then(([flow, cat]) => {
        setLoaded(flow.executions);
        setExecs(flow.executions.map((e) => ({ ...e })));
        setBuiltIn(flow.builtIn);
        setCatalog(cat);
      })
      .catch((e) => setNote({ tone: "error", title: t("authFlow.error.loadFlow"), message: String(e.message ?? e) }));
  }, [api, realmId, alias, t]);
  React.useEffect(reload, [reload]);
  React.useEffect(loadFlows, [loadFlows]);

  // The realm's identity providers, for the idp-redirect step's alias picker (best-effort — the editor
  // still works if the lookup fails; the picker just falls back to a free-text alias).
  const idpClient = React.useMemo(() => idpApi ?? createIdpClient(), [idpApi]);
  React.useEffect(() => {
    idpClient.list(realmId)
      .then((list) => setIdps(list.map((p) => ({ alias: p.alias, displayName: p.displayName }))))
      .catch(() => setIdps([]));
  }, [idpClient, realmId]);

  const dirty = loaded !== null && JSON.stringify(loaded) !== JSON.stringify(execs);
  const journey = React.useMemo(() => toJourney(execs, catalog), [execs, catalog]);
  const preview = React.useMemo(() => previewScreens(journey), [journey]);
  const summary = React.useMemo(() => summarizeJourney(journey), [journey]);
  const conditionCatalog = catalog.filter(isConditionEntry);
  // Identity-provider federation is configured on the Application (Login → Single sign-on), not here —
  // so "idp-redirect" is not offered as an add-able flow method.
  const methodCatalog = catalog.filter((c) => !isConditionEntry(c) && c.id !== "idp-redirect");

  // ---- mutators (shared by both views) ----
  const siblings = (parentId: string | null) =>
    execs.filter((e) => (e.parentId ?? null) === parentId).sort((a, b) => a.priority - b.priority);

  const setRequirement = (id: string, requirement: string) =>
    setExecs((xs) => xs.map((e) => (e.executionId === id ? { ...e, requirement } : e)));

  const remove = (id: string) =>
    setExecs((xs) => xs.filter((e) => e.executionId !== id && e.parentId !== id));

  const move = (id: string, parentId: string | null, dir: -1 | 1) => {
    const sibs = siblings(parentId);
    const idx = sibs.findIndex((s) => s.executionId === id);
    const swap = sibs[idx + dir];
    if (!swap) return;
    const me = sibs[idx];
    setExecs((xs) => xs.map((x) => {
      if (x.executionId === me.executionId) return { ...x, priority: swap.priority };
      if (x.executionId === swap.executionId) return { ...x, priority: me.priority };
      return x;
    }));
  };

  const nextPriority = (parentId: string | null) => {
    const sibs = siblings(parentId);
    return (sibs.length ? Math.max(...sibs.map((s) => s.priority)) : 0) + 10;
  };

  const addStage = () => {
    const id = newId();
    setExecs((xs) => [...xs, { executionId: id, parentId: null, authenticatorId: null, requirement: "REQUIRED", condition: false, priority: nextPriority(null) }]);
  };

  const addToStage = (stageId: string | null, authenticatorId: string, asCondition: boolean) => {
    const cat = catalog.find((c) => c.id === authenticatorId);
    const condition = asCondition || isConditionEntry(cat);
    const requirement = condition ? "REQUIRED" : "ALTERNATIVE";
    setExecs((xs) => [...xs, { executionId: newId(), parentId: stageId, authenticatorId, requirement, condition, priority: nextPriority(stageId) }]);
    setPicker(null);
  };

  const setStageMode = (stage: JourneyStage, selectMode: "ANY" | "ALL") => {
    const req = selectMode === "ANY" ? "ALTERNATIVE" : "REQUIRED";
    const ids = new Set(stage.methods.map((m) => m.execId));
    setExecs((xs) => xs.map((e) => (ids.has(e.executionId) ? { ...e, requirement: req } : e)));
  };

  const save = async () => {
    setBusy(true);
    try {
      const saved = await api.saveByAlias(realmId, alias, execs);
      setLoaded(saved.executions);
      setExecs(saved.executions.map((e) => ({ ...e })));
      setNote({ tone: "success", title: t("authFlow.saved.title"), message: t("authFlow.saved.msg", { alias, realm: realmId }) });
    } catch (e: unknown) {
      setNote({ tone: "error", title: t("authFlow.error.save"), message: String((e as Error).message ?? e) });
    } finally {
      setBusy(false);
    }
  };

  /** Switch the edited flow, warning if the current one has unsaved edits. */
  const switchFlow = (next: string) => {
    if (next === alias) return;
    if (dirty && !window.confirm(t("authFlow.confirm.discard.msg"))) return;
    setAlias(next);
  };

  const createFlow = async (newAlias: string) => {
    const blank = dialog === "create";
    setDialog(null);
    try {
      await api.create(realmId, newAlias, blank ? null : alias);
      loadFlows();
      setAlias(newAlias);
      setNote({
        tone: "success",
        title: t("authFlow.flow.created.title"),
        message: blank
          ? t("authFlow.flow.createdBlank.msg", { name: newAlias })
          : t("authFlow.flow.created.msg", { name: newAlias, source: alias }),
      });
    } catch (e: unknown) {
      setNote({ tone: "error", title: t("authFlow.error.create"), message: String((e as Error).message ?? e) });
    }
  };

  const renameFlow = async (newAlias: string) => {
    setDialog(null);
    const from = alias;
    try {
      await api.rename(realmId, from, newAlias);
      loadFlows();
      setAlias(newAlias);
      setNote({ tone: "success", title: t("authFlow.flow.renamed.title"), message: t("authFlow.flow.renamed.msg", { from, name: newAlias }) });
    } catch (e: unknown) {
      setNote({ tone: "error", title: t("authFlow.error.rename"), message: String((e as Error).message ?? e) });
    }
  };

  const deleteFlow = async () => {
    setConfirmDel(false);
    const gone = alias;
    try {
      await api.remove(realmId, gone);
      setAlias(BROWSER_ALIAS);
      loadFlows();
      setNote({ tone: "success", title: t("authFlow.flow.deleted.title"), message: t("authFlow.flow.deleted.msg", { alias: gone }) });
    } catch (e: unknown) {
      setNote({ tone: "error", title: t("authFlow.error.delete"), message: String((e as Error).message ?? e) });
    }
  };

  return (
    <Page>
      <PageHeader
        title={t("authFlow.title")}
        description={<>{t("authFlow.description.pre")}<strong>{realmId}</strong>{t("authFlow.description.post")}{builtIn && <> <Badge tone="neutral">{t("authFlow.badge.builtIn")}</Badge></>}</>}
        actions={<>
          <Segmented value={mode} onChange={(m) => setModePersist(m as Mode)}
            options={[{ value: "simple", label: t("authFlow.mode.simple") }, { value: "advanced", label: t("authFlow.mode.advanced") }]} />
          {dirty && <span className="hx-unsaved">{t("authFlow.unsaved")}</span>}
          <Button variant="ghost" onClick={reload} disabled={!dirty || busy}>{t("authFlow.action.discard")}</Button>
          <Button variant="primary" onClick={save} disabled={!dirty || busy}>{t("authFlow.action.save")}</Button>
        </>}
      />

      <PageBody>
      <div className="hx-flowbar">
        <div className="hx-flowbar__pick">
          <label htmlFor="hx-flow-select" className="hx-flowbar__label">{t("authFlow.flowbar.label")}</label>
          <div className="hx-flowbar__select">
            <Select id="hx-flow-select" aria-label={t("authFlow.flowbar.aria")} value={alias} onChange={switchFlow}
              options={(flows.length ? flows : [{ realmId, alias: BROWSER_ALIAS, builtIn: true }]).map((f) => ({
                value: f.alias, label: f.builtIn ? `${f.alias}${t("authFlow.flowbar.defaultSuffix")}` : f.alias,
              }))} />
          </div>
        </div>
        <div className="hx-flowbar__actions">
          <Button variant="primary" onClick={() => setDialog("create")}>{t("authFlow.action.new")}</Button>
          <Button variant="ghost" onClick={() => setDialog("new")}>{t("authFlow.action.duplicate")}</Button>
          <Button variant="ghost" onClick={() => setDialog("rename")} disabled={builtIn}>{t("authFlow.action.rename")}</Button>
          <Button variant="ghost" onClick={() => setConfirmDel(true)} disabled={builtIn}>{t("authFlow.action.delete")}</Button>
        </div>
      </div>

      {loaded === null ? (
        <div className="hx-loadwrap"><Spinner size={28} label={t("authFlow.loading")} /></div>
      ) : (
        <>
          {mode === "simple" ? (
            <JourneyView
              stages={journey}
              rootCount={siblings(null).length}
              idps={idps}
              onAddStage={addStage}
              onAddMethod={(stageId, cond) => setPicker({ stageId, condition: cond })}
              onRemove={remove}
              onMoveStage={(id, dir) => move(id, null, dir)}
              onStageRequirement={(id, r) => setRequirement(id, r)}
              onStageMode={setStageMode}
              preview={preview}
            />
          ) : (
            <CanvasView
              execs={execs}
              catalog={catalog}
              siblings={siblings}
              idps={idps}
              onAdd={(parentId, cond) => setPicker({ stageId: parentId, condition: cond })}
              onAddStage={addStage}
              onRemove={remove}
              onMove={move}
              onRequirement={setRequirement}
            />
          )}
          <details className="hx-summary" open>
            <summary><span className="hx-summary__label">{t("authFlow.summary.label")}</span><span className="hx-summary__hint">{t("authFlow.summary.hint")}</span></summary>
            <p className="hx-summary__text">{summary}</p>
          </details>
        </>
      )}
      </PageBody>

      <Modal open={dialog !== null} title={dialog === "rename" ? t("authFlow.modal.rename.title") : dialog === "create" ? t("authFlow.modal.create.title") : t("authFlow.modal.duplicate.title")} onClose={() => setDialog(null)} width={440}>
        {dialog && (
          <FlowNameDialog
            kind={dialog}
            sourceAlias={alias}
            taken={flows.map((f) => f.alias)}
            onSubmit={dialog === "rename" ? renameFlow : createFlow}
            onCancel={() => setDialog(null)}
          />
        )}
      </Modal>

      <ConfirmDialog open={confirmDel} title={t("authFlow.confirm.delete.title")}
        message={t("authFlow.confirm.delete.msg", { alias })}
        onConfirm={deleteFlow} onCancel={() => setConfirmDel(false)} />

      <Modal open={picker !== null} title={picker?.condition ? t("authFlow.picker.condition.title") : t("authFlow.picker.method.title")} onClose={() => setPicker(null)} width={460}>
        {picker && (
          <PickerForm
            entries={picker.condition ? conditionCatalog : methodCatalog}
            kind={picker.condition ? "condition" : "method"}
            onPick={(id) => addToStage(picker.stageId, id, picker.condition)}
            onCancel={() => setPicker(null)}
          />
        )}
      </Modal>

      {note && (
        <div className="hx-toasthost">
          <Toast tone={note.tone} title={note.title} message={note.message} onDismiss={() => setNote(null)} />
        </div>
      )}
    </Page>
  );
}

// ----------------------------------------------------------------------------- Segmented control
function Segmented({ value, onChange, options }: { value: string; onChange: (v: string) => void; options: { value: string; label: string }[]; }) {
  return (
    <div className="hx-seg" role="tablist">
      {options.map((o) => (
        <button key={o.value} role="tab" aria-selected={value === o.value}
          className={`hx-seg__btn${value === o.value ? " is-active" : ""}`} onClick={() => onChange(o.value)}>
          {o.label}
        </button>
      ))}
    </div>
  );
}

// ----------------------------------------------------------------------------- Simple: Journey + preview
function JourneyView({ stages, rootCount, idps, onAddStage, onAddMethod, onRemove, onMoveStage, onStageRequirement, onStageMode, preview }: {
  stages: JourneyStage[];
  rootCount: number;
  idps: IdpOption[];
  onAddStage: () => void;
  onAddMethod: (stageId: string, condition: boolean) => void;
  onRemove: (id: string) => void;
  onMoveStage: (id: string, dir: -1 | 1) => void;
  onStageRequirement: (id: string, r: string) => void;
  onStageMode: (stage: JourneyStage, mode: "ANY" | "ALL") => void;
  preview: ReturnType<typeof previewScreens>;
}) {
  const { t } = useT();
  return (
    <div className="hx-journey">
      <div className="hx-journey__steps">
        {/* Primary factor — implicit, shown so the picture is complete */}
        <div className="hx-stage hx-stage--intro">
          <div className="hx-stage__rail"><span className="hx-stage__dot">1</span></div>
          <div className="hx-stage__body">
            <div className="hx-stage__head">
              <div><strong>{t("authFlow.journey.step1.title")}</strong><div className="hx-stage__sub">{t("authFlow.journey.step1.sub")}</div></div>
              <Badge tone="accent">{t("authFlow.journey.step1.badge")}</Badge>
            </div>
          </div>
        </div>

        {stages.map((s, i) => (
          <div key={s.id} className="hx-stage">
            <div className="hx-stage__rail"><span className="hx-stage__dot">{i + 2}</span></div>
            <div className="hx-stage__body">
              <div className="hx-stage__head">
                <div className="hx-stage__title">
                  <strong>{s.title}</strong>
                  <div className="hx-stage__sub">{requirementMeta(s.requirement).hint}</div>
                </div>
                <div className="hx-stage__headctl">
                  <div className="hx-stage__reqselect">
                    <Select options={REQUIREMENT_OPTIONS} value={s.requirement} onChange={(r) => onStageRequirement(s.id, r)} aria-label={t("authFlow.aria.stageRequirement", { title: s.title })} />
                  </div>
                  <button className="hx-ghosticon" aria-label={t("authFlow.aria.moveUp")} disabled={i === 0} onClick={() => onMoveStage(s.id, -1)}><Chevron dir="up" /></button>
                  <button className="hx-ghosticon" aria-label={t("authFlow.aria.moveDown")} disabled={i === stages.length - 1} onClick={() => onMoveStage(s.id, 1)}><Chevron dir="down" /></button>
                  <button className="hx-ghosticon hx-ghosticon--danger" aria-label={t("authFlow.aria.removeStage", { title: s.title })} onClick={() => onRemove(s.id)}><Cross /></button>
                </div>
              </div>

              {s.conditions.length > 0 && (
                <div className="hx-stage__when">
                  <span className="hx-when-label">{t("authFlow.journey.whenLabel")}</span>
                  {s.conditions.map((c) => (
                    <span key={c.execId} className="hx-chip hx-chip--cond">
                      {c.label}
                      <button className="hx-chip__x" aria-label={t("authFlow.aria.removeCondition", { label: c.label })} onClick={() => onRemove(c.execId)}>×</button>
                    </span>
                  ))}
                </div>
              )}

              {s.isGroup && (
                <>
                  <div className="hx-stage__methods">
                    {s.methods.length === 0 && <span className="hx-stage__empty">{t("authFlow.journey.noMethods")}</span>}
                    {s.methods.map((m) => (
                      <span key={m.execId} className="hx-chip hx-chip--method">
                        {m.label}
                        <button className="hx-chip__x" aria-label={t("authFlow.aria.removeMethod", { label: m.label })} onClick={() => onRemove(m.execId)}>×</button>
                      </span>
                    ))}
                  </div>
                  {s.methods.filter((m) => m.authenticatorId === "idp-redirect").map((m) => (
                    <div key={`cfg-${m.execId}`} className="hx-stage__cfg hx-stage__cfg--readonly">
                      <IdpManagedNote config={m.config} idps={idps} />
                    </div>
                  ))}
                  <div className="hx-stage__foot">
                    <div className="hx-stage__addgroup">
                      <button className="hx-textbtn" onClick={() => onAddMethod(s.id, false)}>{t("authFlow.journey.addMethod")}</button>
                      <button className="hx-textbtn" onClick={() => onAddMethod(s.id, true)}>{t("authFlow.journey.addCondition")}</button>
                    </div>
                    {s.methods.length > 1 && (
                      <Segmented value={s.selectMode} onChange={(v) => onStageMode(s, v as "ANY" | "ALL")}
                        options={[{ value: "ANY", label: t("authFlow.journey.pickOne") }, { value: "ALL", label: t("authFlow.journey.allRequired") }]} />
                    )}
                  </div>
                </>
              )}

              {!s.isGroup && (
                <>
                  <div className="hx-stage__methods">
                    {s.methods.map((m) => (
                      <span key={m.execId} className="hx-chip hx-chip--method">{m.label}</span>
                    ))}
                  </div>
                  {s.methods.filter((m) => m.authenticatorId === "idp-redirect").map((m) => (
                    <div key={`cfg-${m.execId}`} className="hx-stage__cfg hx-stage__cfg--readonly">
                      <IdpManagedNote config={m.config} idps={idps} />
                    </div>
                  ))}
                </>
              )}
            </div>
          </div>
        ))}

        <button className="hx-stage hx-stage--add" onClick={onAddStage}>
          <div className="hx-stage__rail"><span className="hx-stage__dot hx-stage__dot--add">＋</span></div>
          <div className="hx-stage__body"><strong>{t("authFlow.journey.addStage")}</strong><span className="hx-stage__sub">{t("authFlow.journey.addStage.sub")}</span></div>
        </button>
        {rootCount === 0 && <p className="hx-muted hx-stage__railnote">{t("authFlow.journey.noStages")}</p>}
      </div>

      <aside className="hx-preview">
        <div className="hx-preview__label">{t("authFlow.preview.label")}</div>
        <LoginPreview screens={preview} />
      </aside>
    </div>
  );
}

function LoginPreview({ screens }: { screens: ReturnType<typeof previewScreens> }) {
  const { t } = useT();
  return (
    <div className="hx-phone">
      <div className="hx-phone__notch" />
      <div className="hx-phone__screen">
        <PreviewCard title={t("authFlow.preview.signIn")} tag={null}>
          <div className="hx-pv-field"><span>{t("authFlow.preview.email")}</span><i /></div>
          <div className="hx-pv-field"><span>{t("authFlow.preview.password")}</span><i /></div>
          <div className="hx-pv-btn">{t("authFlow.preview.continue")}</div>
        </PreviewCard>
        {screens.map((sc, i) => (
          <PreviewCard key={i} title={sc.title} tag={sc.optional ? t("authFlow.preview.optional") : null}>
            {sc.kind === "consent" ? (
              <div className="hx-pv-consent"><i /><span>{sc.methods[0]}</span></div>
            ) : sc.methods.length > 1 ? (
              <div className="hx-pv-methods">
                {sc.methods.map((m) => <div key={m} className="hx-pv-method">{m}</div>)}
              </div>
            ) : (
              <>
                <div className="hx-pv-field"><span>{sc.methods[0]}</span><i /></div>
                <div className="hx-pv-btn">{t("authFlow.preview.verify")}</div>
              </>
            )}
          </PreviewCard>
        ))}
      </div>
    </div>
  );
}

function PreviewCard({ title, tag, children }: { title: string; tag: string | null; children: React.ReactNode }) {
  return (
    <div className="hx-pvcard">
      <div className="hx-pvcard__head"><span>{title}</span>{tag && <em>{tag}</em>}</div>
      {children}
    </div>
  );
}

// ----------------------------------------------------------------------------- Advanced: flow canvas
function CanvasView({ execs, catalog, siblings, idps, onAdd, onAddStage, onRemove, onMove, onRequirement }: {
  execs: FlowExecution[];
  catalog: AuthenticatorCatalogEntry[];
  siblings: (parentId: string | null) => FlowExecution[];
  idps: IdpOption[];
  onAdd: (parentId: string | null, condition: boolean) => void;
  onAddStage: () => void;
  onRemove: (id: string) => void;
  onMove: (id: string, parentId: string | null, dir: -1 | 1) => void;
  onRequirement: (id: string, r: string) => void;
}) {
  const { t } = useT();
  const [selId, setSelId] = React.useState<string | null>(null);
  const label = (id: string | null) => (id ? catalog.find((c) => c.id === id)?.displayName ?? id : t("authFlow.canvas.group"));
  const roots = siblings(null);
  const sel = selId ? execs.find((e) => e.executionId === selId) ?? null : null;

  return (
    <div className="hx-canvaswrap">
      <div className="hx-canvas">
        <div className="hx-node hx-node--terminal">{t("authFlow.canvas.start")}</div>
        <Arrow />
        <div className="hx-node hx-node--terminal">{t("authFlow.canvas.password")}</div>
        {roots.map((r) => {
          const kids = siblings(r.executionId);
          const isGroup = r.authenticatorId == null;
          return (
            <React.Fragment key={r.executionId}>
              <Arrow />
              {isGroup ? (
                <div className="hx-colgroup">
                  <div className={`hx-grouphead${selId === r.executionId ? " is-sel" : ""}`} onClick={() => setSelId(r.executionId)}>
                    <span>{requirementMeta(r.requirement).label}</span>
                  </div>
                  <div className="hx-colstack">
                    {kids.length === 0 && <button className="hx-node hx-node--ghost" onClick={() => onAdd(r.executionId, false)}>{t("authFlow.canvas.addNode")}</button>}
                    {kids.map((k) => (
                      <button key={k.executionId} className={`hx-node hx-node--${k.condition ? "cond" : "method"}${selId === k.executionId ? " is-sel" : ""}`} onClick={() => setSelId(k.executionId)}>
                        {label(k.authenticatorId)}
                      </button>
                    ))}
                  </div>
                </div>
              ) : (
                <button className={`hx-node hx-node--method${selId === r.executionId ? " is-sel" : ""}`} onClick={() => setSelId(r.executionId)}>{label(r.authenticatorId)}</button>
              )}
            </React.Fragment>
          );
        })}
        <Arrow />
        <div className="hx-node hx-node--terminal hx-node--done">{t("authFlow.canvas.signedIn")}</div>
        <button className="hx-node hx-node--add" onClick={onAddStage}>{t("authFlow.canvas.addStage")}</button>
      </div>

      <aside className="hx-inspector">
        {sel ? (
          <div>
            <div className="hx-inspector__title">{sel.authenticatorId ? label(sel.authenticatorId) : t("authFlow.canvas.group")}</div>
            {sel.authenticatorId && <code className="hx-inspector__id">{sel.authenticatorId}</code>}
            <FormField label={t("authFlow.inspector.whenLabel")}><Select options={REQUIREMENT_OPTIONS} value={sel.requirement} onChange={(r) => onRequirement(sel.executionId, r)} /></FormField>
            {sel.authenticatorId === "idp-redirect" && (
              <IdpManagedNote config={sel.config} idps={idps} />
            )}
            {sel.authenticatorId == null && (
              <div className="hx-badges hx-picksearch">
                <Button variant="ghost" onClick={() => onAdd(sel.executionId, false)}>{t("authFlow.inspector.addMethod")}</Button>
                <Button variant="ghost" onClick={() => onAdd(sel.executionId, true)}>{t("authFlow.inspector.addCondition")}</Button>
              </div>
            )}
            <div className="hx-badges">
              <Button variant="ghost" onClick={() => onMove(sel.executionId, sel.parentId ?? null, -1)}>{t("authFlow.inspector.moveUp")}</Button>
              <Button variant="ghost" onClick={() => onMove(sel.executionId, sel.parentId ?? null, 1)}>{t("authFlow.inspector.moveDown")}</Button>
            </div>
            <button className="hx-inspector__remove" onClick={() => { onRemove(sel.executionId); setSelId(null); }}>{t("authFlow.inspector.remove")}</button>
          </div>
        ) : (
          <div className="hx-inspector__empty">{t("authFlow.inspector.empty.pre")}<strong>{t("authFlow.canvas.addStage")}</strong>{t("authFlow.inspector.empty.post")}</div>
        )}
      </aside>
    </div>
  );
}

// ----------------------------------------------------------------------------- idp-redirect (read-only)
/**
 * Read-only summary of an "Identity Provider Redirector" step. Identity-provider federation is
 * configured on the Application (Login → Single sign-on), not in the flow editor, so here we only
 * describe what it does and point the admin to the app.
 */
function IdpManagedNote({ config, idps }: { config?: Record<string, string>; idps: IdpOption[] }) {
  const { t } = useT();
  const name = (a: string) => idps.find((p) => p.alias === a)?.displayName ?? a;
  const mode = config?.mode ?? "REDIRECT";
  const aliases = (config?.providerAliases || config?.providerAlias || "")
    .split(",").map((s) => s.trim()).filter(Boolean).map(name);
  const summary = mode === "LOCAL_ONLY"
    ? t("authFlow.idp.summaryLocal")
    : mode === "OPTION"
      ? t("authFlow.idp.summaryOption", { providers: aliases.join(", ") || "—" })
      : t("authFlow.idp.summaryRedirect", { provider: aliases[0] ?? "—" });
  return (
    <div className="hx-idpnote">
      <div className="hx-idpnote__summary">{summary}</div>
      <div className="hx-idpnote__managed">{t("authFlow.idp.managed")}</div>
    </div>
  );
}

// ----------------------------------------------------------------------------- name a flow (create / rename)
export function flowNameError(
  value: string,
  taken: string[],
  current?: string,
  t: (key: string, params?: Record<string, string | number>) => string = defaultFlowNameT
): string | null {
  const v = value.trim();
  if (!v) return t("authFlow.error.noName");
  if (!ALIAS_RE.test(v)) return t("authFlow.error.invalidAlias");
  if (v !== current && taken.includes(v)) return t("authFlow.error.alreadyExists", { name: v });
  return null;
}

function FlowNameDialog({ kind, sourceAlias, taken, onSubmit, onCancel }: {
  kind: "new" | "create" | "rename";
  sourceAlias: string;
  taken: string[];
  onSubmit: (alias: string) => void;
  onCancel: () => void;
}) {
  const { t } = useT();
  const [value, setValue] = React.useState(kind === "rename" ? sourceAlias : "");
  const [attempted, setAttempted] = React.useState(false);
  const error = flowNameError(value, taken, kind === "rename" ? sourceAlias : undefined, t);
  const submit = () => { if (error) { setAttempted(true); return; } onSubmit(value.trim()); };
  return (
    <div>
      <p className="hx-modal__lede">
        {kind === "rename"
          ? <>{t("authFlow.nameDialog.rename.pre")}<strong>{sourceAlias}</strong>{t("authFlow.nameDialog.rename.post")}</>
          : kind === "create"
          ? t("authFlow.nameDialog.create")
          : <>{t("authFlow.nameDialog.duplicate.pre")}<strong>{sourceAlias}</strong>{t("authFlow.nameDialog.duplicate.post")}</>}
      </p>
      <FormField label={t("authFlow.form.flowName.label")} required error={attempted ? error ?? undefined : undefined}>
        <Input value={value} autoFocus aria-label={t("authFlow.form.flowName.label")} placeholder={t("authFlow.form.flowName.placeholder")}
          onChange={(e) => setValue(e.target.value)}
          onKeyDown={(e) => { if (e.key === "Enter") submit(); }} />
      </FormField>
      <div className="hx-formactions hx-formactions--end">
        <Button variant="ghost" onClick={onCancel}>{t("common.cancel")}</Button>
        <Button variant="primary" onClick={submit}>{kind === "rename" ? t("authFlow.action.doRename") : t("common.create")}</Button>
      </div>
    </div>
  );
}

// ----------------------------------------------------------------------------- pickers + icons
function PickerForm({ entries, kind, onPick, onCancel }: {
  entries: AuthenticatorCatalogEntry[];
  kind: "method" | "condition";
  onPick: (id: string) => void;
  onCancel: () => void;
}) {
  const { t } = useT();
  const [q, setQ] = React.useState("");
  const list = entries.filter((e) => e.displayName.toLowerCase().includes(q.toLowerCase()));
  return (
    <div>
      <Input className="hx-picksearch" placeholder={kind === "condition" ? t("authFlow.picker.search.condition") : t("authFlow.picker.search.method")} value={q} onChange={(e) => setQ(e.target.value)} autoFocus />
      <div className="hx-pickgrid">
        {list.map((e) => (
          <button key={e.id} className="hx-pickcard" onClick={() => onPick(e.id)}>
            <div className="hx-pickcard__name">{e.displayName}{e.levelOfAssurance > 0 && <LoaBadge level={loaTier(e.levelOfAssurance)} />}</div>
            <code>{e.id}</code>
          </button>
        ))}
        {list.length === 0 && <p className="hx-muted">{t("authFlow.picker.empty")}</p>}
      </div>
      <div className="hx-formactions hx-formactions--end">
        <Button variant="ghost" onClick={onCancel}>{t("common.cancel")}</Button>
      </div>
    </div>
  );
}

const Chevron = ({ dir }: { dir: "up" | "down" }) => (
  <svg width="12" height="12" viewBox="0 0 24 24" fill="none" aria-hidden="true">
    <path d={dir === "up" ? "M6 15l6-6 6 6" : "M6 9l6 6 6-6"} stroke="currentColor" strokeWidth="2.4" strokeLinecap="round" strokeLinejoin="round" />
  </svg>
);
const Cross = () => (
  <svg width="15" height="15" viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="M6 6l12 12M18 6L6 18" stroke="currentColor" strokeWidth="2" strokeLinecap="round" /></svg>
);
const Arrow = () => <span className="hx-arrow" aria-hidden="true" />;
