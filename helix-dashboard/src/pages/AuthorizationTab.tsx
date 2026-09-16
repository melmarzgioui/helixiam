import React from "react";
import { Page, PageHeader, PageBody, PageToolbar } from "../components/Page";
import { Card } from "../components/Card";
import { Alert } from "../components/Alert";
import { Button } from "../components/Button";
import { Modal } from "../components/Modal";
import { Spinner } from "../components/Spinner";
import { FormField, Input } from "../components/FormField";
import { Select } from "../components/Select";
import { Checkbox } from "../components/Choice";
import { RowMenu } from "../components/RowMenu";
import { Tabs } from "../components/Tabs";
import { AuthzApi, AuthzServer, AuthzResource, AuthzScope, AuthzPolicy, AuthzPermission, AuthzEvalResult } from "../api/authz";
import { RoleApi } from "../api/roles";
import { ClientRoleApi } from "../api/clientRoles";
import { useT } from "../i18n/LocaleContext";

type Sub = "settings" | "resources" | "scopes" | "policies" | "permissions" | "evaluate";

export function AuthorizationTab({ authzApi, roleApi, clientRoleApi, realmId, clientId, onError }: {
  authzApi: AuthzApi; roleApi: RoleApi; clientRoleApi: ClientRoleApi; realmId: string; clientId: string; onError: (m: string) => void;
}) {
  const { t } = useT();
  const [sub, setSub] = React.useState<Sub>("settings");
  const [server, setServer] = React.useState<AuthzServer | null>(null);
  const [scopes, setScopes] = React.useState<AuthzScope[]>([]);
  const [resources, setResources] = React.useState<AuthzResource[]>([]);
  const [policies, setPolicies] = React.useState<AuthzPolicy[]>([]);
  const [permissions, setPermissions] = React.useState<AuthzPermission[]>([]);
  const [roleNames, setRoleNames] = React.useState<string[]>([]);
  const [loaded, setLoaded] = React.useState(false);

  const reload = React.useCallback(() => {
    Promise.all([
      authzApi.getSettings(realmId, clientId), authzApi.listScopes(realmId, clientId),
      authzApi.listResources(realmId, clientId), authzApi.listPolicies(realmId, clientId),
      authzApi.listPermissions(realmId, clientId),
    ]).then(([s, sc, re, po, pe]) => { setServer(s); setScopes(sc); setResources(re); setPolicies(po); setPermissions(pe); setLoaded(true); })
      .catch((e) => { onError(String(e.message ?? e)); setLoaded(true); });
  }, [authzApi, realmId, clientId, onError]);
  React.useEffect(reload, [reload]);
  React.useEffect(() => {
    Promise.all([roleApi.list(realmId), clientRoleApi.listRoles(realmId, clientId)])
      .then(([r, cr]) => setRoleNames([...new Set([...r.map((x) => x.name), ...cr.map((x) => x.name)])]))
      .catch(() => undefined);
  }, [roleApi, clientRoleApi, realmId, clientId]);

  const SUBS: { id: Sub; label: string }[] = [
    { id: "settings", label: t("authorization.tab.general") },
    { id: "resources", label: t("authorization.tab.resources") },
    { id: "scopes", label: t("authorization.tab.scopes") },
    { id: "policies", label: t("authorization.tab.policies") },
    { id: "permissions", label: t("authorization.tab.permissions") },
    { id: "evaluate", label: t("authorization.tab.evaluate") },
  ];
  const authzOff = !(server?.enabled);

  if (!loaded) return <div className="hx-loadwrap"><Spinner size={24} label={t("authorization.loading")} /></div>;

  return (
    <Page>
      <PageHeader
        title={t("authorization.title")}
        description={t("authorization.description")}
      />
      <PageBody>
        <Tabs tabs={SUBS} value={sub} onChange={(id) => setSub(id as Sub)} />

        {authzOff && sub !== "settings" && (
          <Alert tone="warning">
            {t("authorization.alert.warning.pre")}<strong>{t("authorization.alert.warning.off")}</strong>{t("authorization.alert.warning.post")}{" "}
            <button type="button" className="hx-textbtn" onClick={() => setSub("settings")}>{t("authorization.tab.general")}</button>.
          </Alert>
        )}
        {sub === "settings" && <SettingsPanel server={server} onSave={(en, ds) => authzApi.saveSettings(realmId, clientId, en, ds).then(setServer).catch((e) => onError(String(e.message ?? e)))} />}
        {sub === "scopes" && <NameListPanel title={t("authorization.scope.col")} empty={t("authorization.scope.empty")} modalTitle={t("authorization.scope.modalTitle")} rows={scopes.map((s) => s.name)}
          onAdd={(n) => authzApi.createScope(realmId, clientId, n).then(reload).catch((e) => onError(String(e.message ?? e)))}
          onDelete={(n) => authzApi.removeScope(realmId, clientId, n).then(reload).catch((e) => onError(String(e.message ?? e)))} />}
        {sub === "resources" && <ResourcePanel resources={resources} scopes={scopes.map((s) => s.name)}
          onAdd={(n, uris, sc) => authzApi.createResource(realmId, clientId, n, uris, sc).then(reload).catch((e) => onError(String(e.message ?? e)))}
          onDelete={(n) => authzApi.removeResource(realmId, clientId, n).then(reload).catch((e) => onError(String(e.message ?? e)))} />}
        {sub === "policies" && <PolicyPanel policies={policies} roleNames={roleNames}
          onAdd={(n, logic, roles) => authzApi.createPolicy(realmId, clientId, n, logic, roles).then(reload).catch((e) => onError(String(e.message ?? e)))}
          onDelete={(n) => authzApi.removePolicy(realmId, clientId, n).then(reload).catch((e) => onError(String(e.message ?? e)))} />}
        {sub === "permissions" && <PermissionPanel permissions={permissions} resources={resources.map((r) => r.name)} scopes={scopes.map((s) => s.name)} policies={policies.map((p) => p.name)}
          onAdd={(body) => authzApi.createPermission(realmId, clientId, body).then(reload).catch((e) => onError(String(e.message ?? e)))}
          onDelete={(n) => authzApi.removePermission(realmId, clientId, n).then(reload).catch((e) => onError(String(e.message ?? e)))} />}
        {sub === "evaluate" && <EvaluatePanel roleNames={roleNames} resources={resources.map((r) => r.name)} scopes={scopes.map((s) => s.name)}
          onRun={(body) => authzApi.evaluate(realmId, clientId, body)} onError={onError} />}
      </PageBody>
    </Page>
  );
}

function SettingsPanel({ server, onSave }: { server: AuthzServer | null; onSave: (enabled: boolean, ds: string) => void }) {
  const { t } = useT();
  const [enabled, setEnabled] = React.useState(server?.enabled ?? false);
  const [ds, setDs] = React.useState(server?.decisionStrategy ?? "UNANIMOUS");
  React.useEffect(() => { setEnabled(server?.enabled ?? false); setDs(server?.decisionStrategy ?? "UNANIMOUS"); }, [server]);
  return (
    <Card>
      <Checkbox label={t("authorization.settings.enable")} checked={enabled} onChange={setEnabled} />
      <FormField label={t("authorization.settings.decisionStrategy.label")} hint={t("authorization.settings.decisionStrategy.hint")}>
        <Select aria-label={t("authorization.settings.decisionStrategy.label")} value={ds} onChange={setDs} options={[{ value: "UNANIMOUS", label: t("authorization.settings.unanimous") }, { value: "AFFIRMATIVE", label: t("authorization.settings.affirmative") }]} />
      </FormField>
      <div className="hx-formactions hx-formactions--end">
        <Button variant="primary" onClick={() => onSave(enabled, ds)}>{t("common.save")}</Button>
      </div>
    </Card>
  );
}

function Table({ head, children }: { head: React.ReactNode; children: React.ReactNode }) {
  return <div className="hx-tablescroll"><table className="hx-table"><thead><tr>{head}</tr></thead><tbody>{children}</tbody></table></div>;
}

function NameListPanel({ title, empty, rows, onAdd, onDelete, modalTitle }: { title: string; empty: string; rows: string[]; onAdd: (n: string) => void; onDelete: (n: string) => void; modalTitle?: string }) {
  const { t } = useT();
  const [draft, setDraft] = React.useState<string | null>(null);
  return (
    <div>
      <PageToolbar><div className="hx-toolbar__spacer" /><Button variant="primary" onClick={() => setDraft("")}>{t("authorization.action.add")}</Button></PageToolbar>
      {rows.length === 0 ? <p className="hx-muted">{empty}</p> : (
        <div className="hx-card">
          <Table head={<><th>{title}</th><th className="hx-col-actions" aria-label={t("authorization.col.actions")} /></>}>
            {rows.map((n) => <tr key={n}><td><code>{n}</code></td><td className="hx-cell-right"><RowMenu items={[{ label: t("common.delete"), danger: true, onSelect: () => onDelete(n) }]} /></td></tr>)}
          </Table>
        </div>
      )}
      <Modal open={draft !== null} title={modalTitle ?? `Add ${title.toLowerCase()}`} onClose={() => setDraft(null)} width={420}>
        <FormField label={t("authorization.field.name")} required><Input value={draft ?? ""} onChange={(e) => setDraft(e.target.value)} placeholder={t("authorization.scope.namePlaceholder")} /></FormField>
        <div className="hx-formactions hx-formactions--end">
          <Button variant="ghost" onClick={() => setDraft(null)}>{t("common.cancel")}</Button>
          <Button variant="primary" onClick={() => { if (draft?.trim()) { onAdd(draft.trim()); setDraft(null); } }}>{t("authorization.action.add")}</Button>
        </div>
      </Modal>
    </div>
  );
}

function Chips({ items }: { items: string[] }) {
  return <span className="hx-badges">{items.length === 0 ? <span className="hx-faint">—</span> : items.map((i) => <span key={i} className="hx-chip hx-chip--method">{i}</span>)}</span>;
}

function MultiCheck({ label, options, selected, onToggle }: { label: string; options: string[]; selected: string[]; onToggle: (v: string, on: boolean) => void }) {
  const { t } = useT();
  return (
    <FormField label={label}>
      {options.length === 0 ? <p className="hx-help">{t("authorization.field.noneYet")}</p> : (
        <div className="hx-badges">
          {options.map((o) => <Checkbox key={o} label={o} checked={selected.includes(o)} onChange={(on) => onToggle(o, on)} />)}
        </div>
      )}
    </FormField>
  );
}

function ResourcePanel({ resources, scopes, onAdd, onDelete }: { resources: AuthzResource[]; scopes: string[]; onAdd: (n: string, uris: string[], scopes: string[]) => void; onDelete: (n: string) => void }) {
  const { t } = useT();
  const [open, setOpen] = React.useState(false);
  const [name, setName] = React.useState(""); const [uris, setUris] = React.useState(""); const [sel, setSel] = React.useState<string[]>([]);
  const reset = () => { setName(""); setUris(""); setSel([]); };
  return (
    <div>
      <PageToolbar><div className="hx-toolbar__spacer" /><Button variant="primary" onClick={() => { reset(); setOpen(true); }}>{t("authorization.resource.create")}</Button></PageToolbar>
      {resources.length === 0 ? <p className="hx-muted">{t("authorization.resource.empty")}</p> : (
        <div className="hx-card">
          <Table head={<><th>{t("authorization.field.name")}</th><th>{t("authorization.resource.col.uris")}</th><th>{t("authorization.resource.col.scopes")}</th><th className="hx-col-actions" aria-label={t("authorization.col.actions")} /></>}>
            {resources.map((r) => <tr key={r.id}><td><code>{r.name}</code></td><td><Chips items={r.uris} /></td><td><Chips items={r.scopes} /></td>
              <td className="hx-cell-right"><RowMenu items={[{ label: t("common.delete"), danger: true, onSelect: () => onDelete(r.name) }]} /></td></tr>)}
          </Table>
        </div>
      )}
      <Modal open={open} title={t("authorization.resource.modalTitle")} onClose={() => setOpen(false)} width={520}>
        <FormField label={t("authorization.field.name")} required><Input value={name} onChange={(e) => setName(e.target.value)} placeholder={t("authorization.resource.field.name.placeholder")} /></FormField>
        <FormField label={t("authorization.resource.field.uris")} hint={t("authorization.resource.field.uris.hint")}><Input value={uris} onChange={(e) => setUris(e.target.value)} placeholder={t("authorization.resource.field.uris.placeholder")} /></FormField>
        <MultiCheck label={t("authorization.resource.col.scopes")} options={scopes} selected={sel} onToggle={(v, on) => setSel((s) => on ? [...s, v] : s.filter((x) => x !== v))} />
        <div className="hx-formactions hx-formactions--end">
          <Button variant="ghost" onClick={() => setOpen(false)}>{t("common.cancel")}</Button>
          <Button variant="primary" onClick={() => { if (name.trim()) { onAdd(name.trim(), uris.split(",").map((x) => x.trim()).filter(Boolean), sel); setOpen(false); } }}>{t("common.create")}</Button>
        </div>
      </Modal>
    </div>
  );
}

function PolicyPanel({ policies, roleNames, onAdd, onDelete }: { policies: AuthzPolicy[]; roleNames: string[]; onAdd: (n: string, logic: string, roles: string[]) => void; onDelete: (n: string) => void }) {
  const { t } = useT();
  const [open, setOpen] = React.useState(false);
  const [name, setName] = React.useState(""); const [logic, setLogic] = React.useState("POSITIVE"); const [sel, setSel] = React.useState<string[]>([]);
  return (
    <div>
      <PageToolbar><div className="hx-toolbar__spacer" /><Button variant="primary" onClick={() => { setName(""); setLogic("POSITIVE"); setSel([]); setOpen(true); }}>{t("authorization.policy.create")}</Button></PageToolbar>
      {policies.length === 0 ? <p className="hx-muted">{t("authorization.policy.empty")}</p> : (
        <div className="hx-card">
          <Table head={<><th>{t("authorization.field.name")}</th><th>{t("authorization.policy.col.logic")}</th><th>{t("authorization.policy.col.roles")}</th><th className="hx-col-actions" aria-label={t("authorization.col.actions")} /></>}>
            {policies.map((p) => <tr key={p.id}><td><code>{p.name}</code></td><td>{p.logic === "NEGATIVE" ? t("authorization.policy.negative") : t("authorization.policy.positive")}</td><td><Chips items={p.roles} /></td>
              <td className="hx-cell-right"><RowMenu items={[{ label: t("common.delete"), danger: true, onSelect: () => onDelete(p.name) }]} /></td></tr>)}
          </Table>
        </div>
      )}
      <Modal open={open} title={t("authorization.policy.modalTitle")} onClose={() => setOpen(false)} width={520}>
        <FormField label={t("authorization.field.name")} required><Input value={name} onChange={(e) => setName(e.target.value)} placeholder={t("authorization.policy.field.name.placeholder")} /></FormField>
        <FormField label={t("authorization.policy.field.logic")} hint={t("authorization.policy.field.logic.hint")}>
          <Select aria-label={t("authorization.policy.field.logic")} value={logic} onChange={setLogic} options={[{ value: "POSITIVE", label: t("authorization.policy.positive") }, { value: "NEGATIVE", label: t("authorization.policy.negative") }]} />
        </FormField>
        <MultiCheck label={t("authorization.policy.col.roles")} options={roleNames} selected={sel} onToggle={(v, on) => setSel((s) => on ? [...s, v] : s.filter((x) => x !== v))} />
        <div className="hx-formactions hx-formactions--end">
          <Button variant="ghost" onClick={() => setOpen(false)}>{t("common.cancel")}</Button>
          <Button variant="primary" onClick={() => { if (name.trim() && sel.length) { onAdd(name.trim(), logic, sel); setOpen(false); } }}>{t("common.create")}</Button>
        </div>
      </Modal>
    </div>
  );
}

function PermissionPanel({ permissions, resources, scopes, policies, onAdd, onDelete }: {
  permissions: AuthzPermission[]; resources: string[]; scopes: string[]; policies: string[];
  onAdd: (body: { name: string; type: string; resourceName: string | null; scopeName: string | null; policies: string[]; decisionStrategy: string }) => void; onDelete: (n: string) => void;
}) {
  const { t } = useT();
  const [open, setOpen] = React.useState(false);
  const [name, setName] = React.useState(""); const [type, setType] = React.useState("RESOURCE");
  const [resource, setResource] = React.useState(""); const [scope, setScope] = React.useState(""); const [sel, setSel] = React.useState<string[]>([]); const [ds, setDs] = React.useState("UNANIMOUS");
  return (
    <div>
      <PageToolbar><div className="hx-toolbar__spacer" /><Button variant="primary" onClick={() => { setName(""); setType("RESOURCE"); setResource(""); setScope(""); setSel([]); setDs("UNANIMOUS"); setOpen(true); }}>{t("authorization.permission.create")}</Button></PageToolbar>
      {permissions.length === 0 ? <p className="hx-muted">{t("authorization.permission.empty")}</p> : (
        <div className="hx-card">
          <Table head={<><th>{t("authorization.field.name")}</th><th>{t("authorization.permission.col.type")}</th><th>{t("authorization.permission.col.target")}</th><th>{t("authorization.permission.col.policies")}</th><th className="hx-col-actions" aria-label={t("authorization.col.actions")} /></>}>
            {permissions.map((p) => <tr key={p.id}><td><code>{p.name}</code></td><td>{p.type === "SCOPE" ? t("authorization.permission.type.scope") : t("authorization.permission.type.resource")}</td>
              <td><code>{p.type === "SCOPE" ? p.scopeName : p.resourceName}</code></td><td><Chips items={p.policies} /></td>
              <td className="hx-cell-right"><RowMenu items={[{ label: t("common.delete"), danger: true, onSelect: () => onDelete(p.name) }]} /></td></tr>)}
          </Table>
        </div>
      )}
      <Modal open={open} title={t("authorization.permission.modalTitle")} onClose={() => setOpen(false)} width={540}>
        <FormField label={t("authorization.field.name")} required><Input value={name} onChange={(e) => setName(e.target.value)} placeholder={t("authorization.permission.field.name.placeholder")} /></FormField>
        <FormField label={t("authorization.permission.field.type")}><Select aria-label={t("authorization.permission.field.type")} value={type} onChange={setType} options={[{ value: "RESOURCE", label: t("authorization.permission.type.resourceBased") }, { value: "SCOPE", label: t("authorization.permission.type.scopeBased") }]} /></FormField>
        {type === "RESOURCE"
          ? <FormField label={t("authorization.field.resource")} required><Select aria-label={t("authorization.field.resource")} value={resource} onChange={setResource} options={[{ value: "", label: t("authorization.permission.selectResource") }, ...resources.map((r) => ({ value: r, label: r }))]} /></FormField>
          : <FormField label={t("authorization.field.scope")} required><Select aria-label={t("authorization.field.scope")} value={scope} onChange={setScope} options={[{ value: "", label: t("authorization.permission.selectScope") }, ...scopes.map((s) => ({ value: s, label: s }))]} /></FormField>}
        <MultiCheck label={t("authorization.permission.field.applyPolicies")} options={policies} selected={sel} onToggle={(v, on) => setSel((s) => on ? [...s, v] : s.filter((x) => x !== v))} />
        <FormField label={t("authorization.settings.decisionStrategy.label")}><Select aria-label={t("authorization.permission.decisionStrategy.aria")} value={ds} onChange={setDs} options={[{ value: "UNANIMOUS", label: t("authorization.settings.unanimous") }, { value: "AFFIRMATIVE", label: t("authorization.settings.affirmative") }]} /></FormField>
        <div className="hx-formactions hx-formactions--end">
          <Button variant="ghost" onClick={() => setOpen(false)}>{t("common.cancel")}</Button>
          <Button variant="primary" onClick={() => {
            const target = type === "RESOURCE" ? resource : scope;
            if (name.trim() && target && sel.length) { onAdd({ name: name.trim(), type, resourceName: type === "RESOURCE" ? resource : null, scopeName: type === "SCOPE" ? scope : null, policies: sel, decisionStrategy: ds }); setOpen(false); }
          }}>{t("common.create")}</Button>
        </div>
      </Modal>
    </div>
  );
}

function EvaluatePanel({ roleNames, resources, scopes, onRun, onError }: {
  roleNames: string[]; resources: string[]; scopes: string[]; onRun: (body: { username: string | null; roles: string[]; resourceName: string | null; scopeName: string | null }) => Promise<AuthzEvalResult>; onError: (m: string) => void;
}) {
  const { t } = useT();
  const [roles, setRoles] = React.useState<string[]>([]); const [resource, setResource] = React.useState(""); const [scope, setScope] = React.useState("");
  const [result, setResult] = React.useState<AuthzEvalResult | null>(null); const [busy, setBusy] = React.useState(false);
  const run = async () => {
    setBusy(true); setResult(null);
    try { setResult(await onRun({ username: null, roles, resourceName: resource || null, scopeName: scope || null })); }
    catch (e: unknown) { onError(String((e as Error).message ?? e)); }
    finally { setBusy(false); }
  };
  return (
    <Card>
      <p className="hx-muted">{t("authorization.evaluate.description")}</p>
      <MultiCheck label={t("authorization.evaluate.field.roles")} options={roleNames} selected={roles} onToggle={(v, on) => setRoles((s) => on ? [...s, v] : s.filter((x) => x !== v))} />
      <div className="hx-section__body--cols">
        <FormField label={t("authorization.field.resource")}><Select aria-label={t("authorization.field.resource")} value={resource} onChange={setResource} options={[{ value: "", label: t("authorization.evaluate.any") }, ...resources.map((r) => ({ value: r, label: r }))]} /></FormField>
        <FormField label={t("authorization.field.scope")}><Select aria-label={t("authorization.field.scope")} value={scope} onChange={setScope} options={[{ value: "", label: t("authorization.evaluate.any") }, ...scopes.map((s) => ({ value: s, label: s }))]} /></FormField>
      </div>
      <div className="hx-formactions"><Button variant="primary" onClick={run} disabled={busy}>{t("authorization.evaluate.action")}</Button></div>
      {result && (
        <div ref={(el) => el?.scrollIntoView({ behavior: "smooth", block: "nearest" })}>
          <Alert tone={result.granted ? "success" : "danger"} title={result.granted ? t("authorization.evaluate.result.permit") : t("authorization.evaluate.result.deny")}>
            <p className="hx-muted">{result.granted ? t("authorization.evaluate.result.granted") : t("authorization.evaluate.result.denied")}</p>
            <div><span className="hx-faint">{t("authorization.evaluate.result.granting")}</span><Chips items={result.grantingPermissions} /></div>
            <div><span className="hx-faint">{t("authorization.evaluate.result.denying")}</span><Chips items={result.denyingPermissions} /></div>
          </Alert>
        </div>
      )}
    </Card>
  );
}
