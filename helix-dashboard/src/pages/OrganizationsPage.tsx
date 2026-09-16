import React from "react";
import { Page, PageHeader, PageBody, Section } from "../components/Page";
import { Card } from "../components/Card";
import { Button } from "../components/Button";
import { RowMenu } from "../components/RowMenu";
import { Modal, ConfirmDialog } from "../components/Modal";
import { Toast, ToastTone } from "../components/Toast";
import { EmptyState } from "../components/EmptyState";
import { Spinner } from "../components/Spinner";
import { Badge } from "../components/Badge";
import { Switch } from "../components/Switch";
import { FormField, Input, Select } from "../components/FormField";
import {
  OrganizationApi,
  Organization,
  OrganizationWrite,
  OrgMember,
  organizationLabel,
  parseDomains,
  validateOrganization,
} from "../api/organizations";
import { UserApi, UserSummary } from "../api/users";
import { useT } from "../i18n/LocaleContext";

export interface OrganizationsPageProps {
  api: OrganizationApi;
  userApi: UserApi;
  realmId: string;
}

interface Note { tone: ToastTone; title: string; message?: string; }

const ORG_ROLES = ["member", "admin"];

/** Helix IAM Organizations: the live Organizations screen — B2B tenants (list/create/edit/delete + members). */
export function OrganizationsPage({ api, userApi, realmId }: OrganizationsPageProps) {
  const { t } = useT();
  const [orgs, setOrgs] = React.useState<Organization[] | null>(null);
  const [selectedId, setSelectedId] = React.useState<string | null>(null);
  const [editing, setEditing] = React.useState<Organization | "new" | null>(null);
  const [toDelete, setToDelete] = React.useState<Organization | null>(null);
  const [note, setNote] = React.useState<Note | null>(null);

  const reload = React.useCallback(() => {
    setOrgs(null);
    api.list(realmId).then((os) => {
      setOrgs(os);
      setSelectedId((cur) => (cur && os.some((o) => o.orgId === cur) ? cur : os[0]?.orgId ?? null));
    }).catch((e) => {
      setOrgs([]);
      setNote({ tone: "error", title: t("organizations.load.error"), message: String(e.message ?? e) });
    });
  }, [api, realmId, t]);

  React.useEffect(reload, [reload]);

  const selected = orgs?.find((o) => o.orgId === selectedId) ?? null;

  const submit = async (body: OrganizationWrite) => {
    try {
      if (editing === "new") {
        const created = await api.create(realmId, body);
        setNote({ tone: "success", title: t("organizations.created"), message: t("organizations.created.msg", { name: organizationLabel(created) }) });
        setEditing(null);
        reload();
        setSelectedId(created.orgId);
      } else if (editing) {
        await api.update(realmId, editing.orgId, body);
        setNote({ tone: "success", title: t("organizations.saved") });
        setEditing(null);
        reload();
      }
    } catch (e: unknown) {
      setNote({ tone: "error", title: t("organizations.save.error"), message: String((e as Error).message ?? e) });
    }
  };

  const confirmDelete = async () => {
    if (!toDelete) return;
    const target = toDelete;
    setToDelete(null);
    try {
      await api.remove(realmId, target.orgId);
      setNote({ tone: "info", title: t("organizations.deleted"), message: t("organizations.deleted.msg", { name: organizationLabel(target) }) });
      reload();
    } catch (e: unknown) {
      setNote({ tone: "error", title: t("organizations.delete.error"), message: String((e as Error).message ?? e) });
    }
  };

  return (
    <Page>
      <PageHeader
        title={t("organizations.title")}
        description={t("organizations.description", { realm: realmId })}
        actions={<Button variant="primary" onClick={() => setEditing("new")}>{t("organizations.new")}</Button>}
      />

      <PageBody>
        {orgs === null ? (
          <div className="hx-loadwrap">
            <Spinner size={28} label={t("organizations.loading")} />
          </div>
        ) : orgs.length === 0 ? (
          <EmptyState
            title={t("organizations.empty.title")}
            message={t("organizations.empty.msg")}
            action={<Button variant="primary" onClick={() => setEditing("new")}>{t("organizations.new")}</Button>}
          />
        ) : (
          <div className="hx-detailgrid">
            <Card>
              <div>
                {[...orgs].sort((a, b) => organizationLabel(a).localeCompare(organizationLabel(b))).map((o) => {
                  const active = o.orgId === selectedId;
                  return (
                    <div
                      key={o.orgId}
                      className={active ? "hx-navitem hx-navitem--active" : "hx-navitem"}
                      onClick={() => setSelectedId(o.orgId)}
                    >
                      <span className="hx-navitem__icon">
                        <svg width="15" height="15" viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="M3 21h18M5 21V7l7-4 7 4v14M9 9h.01M9 13h.01M9 17h.01M15 9h.01M15 13h.01M15 17h.01" stroke="currentColor" strokeWidth="1.7" strokeLinejoin="round" strokeLinecap="round" /></svg>
                      </span>
                      <span className="hx-navitem__grow">{organizationLabel(o)}</span>
                      {!o.enabled && <Badge tone="warning">{t("organizations.badge.disabled")}</Badge>}
                      {o.memberCount > 0 && <Badge tone="neutral">{o.memberCount}</Badge>}
                      <span onClick={(e) => e.stopPropagation()}>
                        <RowMenu ariaLabel={t("organizations.row.actions", { name: organizationLabel(o) })} items={[
                          { label: t("common.edit"), onSelect: () => setEditing(o) },
                          { label: t("organizations.row.delete"), danger: true, onSelect: () => setToDelete(o) },
                        ]} />
                      </span>
                    </div>
                  );
                })}
              </div>
            </Card>

            {selected ? (
              <OrgDetail
                key={selected.orgId}
                api={api}
                userApi={userApi}
                realmId={realmId}
                org={selected}
                onEdit={() => setEditing(selected)}
                onChanged={reload}
                onError={(m) => setNote({ tone: "error", title: t("organizations.actionFailed"), message: m })}
              />
            ) : (
              <Card><p className="hx-muted">{t("organizations.select.hint")}</p></Card>
            )}
          </div>
        )}
      </PageBody>

      <Modal open={editing !== null} title={editing === "new" ? t("organizations.modal.new") : t("organizations.modal.edit")} onClose={() => setEditing(null)} width={520}>
        {editing !== null && (
          <OrgForm
            initial={editing === "new" ? null : editing}
            onSubmit={submit}
            onCancel={() => setEditing(null)}
          />
        )}
      </Modal>

      <ConfirmDialog
        open={toDelete !== null}
        title={t("organizations.confirm.delete.title")}
        message={t("organizations.confirm.delete.msg", { name: toDelete ? organizationLabel(toDelete) : "" })}
        onConfirm={confirmDelete}
        onCancel={() => setToDelete(null)}
      />

      {note && (
        <div className="hx-toasthost">
          <Toast tone={note.tone} title={note.title} message={note.message} onDismiss={() => setNote(null)} />
        </div>
      )}
    </Page>
  );
}

function OrgDetail({ api, userApi, realmId, org, onEdit, onChanged, onError }: {
  api: OrganizationApi; userApi: UserApi; realmId: string; org: Organization;
  onEdit: () => void; onChanged: () => void; onError: (m: string) => void;
}) {
  const { t } = useT();
  const [members, setMembers] = React.useState<OrgMember[] | null>(null);
  const [allUsers, setAllUsers] = React.useState<UserSummary[]>([]);
  const [addUser, setAddUser] = React.useState("");
  const [addRole, setAddRole] = React.useState("member");

  const load = React.useCallback(() => {
    api.members(realmId, org.orgId).then(setMembers).catch((e) => onError(String(e.message ?? e)));
  }, [api, realmId, org.orgId, onError]);

  React.useEffect(() => {
    load();
    userApi.list(realmId).then(setAllUsers).catch(() => undefined);
  }, [load, userApi, realmId]);

  const candidates = allUsers.filter((u) => !(members ?? []).some((m) => m.userId === u.userId));
  const wrap = (p: Promise<unknown>) => p.then(() => { load(); onChanged(); }).catch((e: Error) => onError(String(e.message ?? e)));

  return (
    <div className="hx-pagebody">
      <Section
        title={organizationLabel(org)}
        description={org.name}
        actions={<Button variant="ghost" onClick={onEdit}>{t("common.edit")}</Button>}
      >
        <div className="hx-colstack">
          <div className="hx-when-label">{t("organizations.detail.domains")}</div>
          {org.domains.length === 0 ? (
            <p className="hx-faint">{t("organizations.detail.noDomains")}</p>
          ) : (
            <div className="hx-badges">
              {org.domains.map((d) => (
                <span key={d} className="hx-chip">{d}</span>
              ))}
            </div>
          )}
        </div>
      </Section>

      <Section
        title={t("organizations.detail.members")}
        description={<>{t("organizations.detail.members.hint.a")}<code>organizations</code>{t("organizations.detail.members.hint.b")}</>}
      >
        <div className="hx-pagebody">
          {members === null ? (
            <Spinner size={20} label={t("common.loading")} />
          ) : members.length === 0 ? (
            <p className="hx-faint">{t("organizations.detail.noMembers")}</p>
          ) : (
            <div className="hx-togglelist">
              {members.map((m) => (
                <div className="hx-togglerow" key={m.userId}>
                  <span className="hx-togglerow__label">{m.username}</span>
                  <span className="hx-badges">
                    <Badge tone={m.role === "admin" ? "accent" : "neutral"}>{m.role}</Badge>
                    <Button variant="ghost" onClick={() => wrap(api.removeMember(realmId, org.orgId, m.userId))}>{t("organizations.detail.remove")}</Button>
                  </span>
                </div>
              ))}
            </div>
          )}
          <div className="hx-toolbar">
            <div className="hx-toolbar__grow">
              <Select
                options={[{ value: "", label: candidates.length ? t("organizations.detail.addUser") : t("organizations.detail.allMembers") }, ...candidates.map((u) => ({ value: u.userId, label: u.username }))]}
                value={addUser} onChange={setAddUser} aria-label={t("organizations.detail.addMember.aria")}
              />
            </div>
            <Select options={ORG_ROLES.map((r) => ({ value: r, label: r }))} value={addRole} onChange={setAddRole} aria-label={t("organizations.detail.memberRole.aria")} />
            <Button variant="primary" disabled={!addUser} onClick={() => { wrap(api.addMember(realmId, org.orgId, addUser, addRole)); setAddUser(""); setAddRole("member"); }}>{t("organizations.detail.add")}</Button>
          </div>
        </div>
      </Section>
    </div>
  );
}

function OrgForm({ initial, onSubmit, onCancel }: {
  initial: Organization | null; onSubmit: (body: OrganizationWrite) => void; onCancel: () => void;
}) {
  const { t } = useT();
  const [name, setName] = React.useState(initial?.name ?? "");
  const [displayName, setDisplayName] = React.useState(initial?.displayName ?? "");
  const [domainsText, setDomainsText] = React.useState((initial?.domains ?? []).join(", "));
  const [enabled, setEnabled] = React.useState(initial?.enabled ?? true);
  const [errors, setErrors] = React.useState<Record<string, string>>({});

  const save = () => {
    const body: OrganizationWrite = {
      name: name.trim(),
      displayName: displayName.trim() || null,
      domains: parseDomains(domainsText),
      enabled,
    };
    const errs = validateOrganization(body);
    setErrors(errs);
    if (Object.keys(errs).length === 0) {
      onSubmit(body);
    }
  };

  return (
    <div>
      <FormField label={t("organizations.form.name")} required hint={t("organizations.form.name.hint")} error={errors.name}>
        <Input value={name} autoFocus placeholder="acme" onChange={(e) => setName(e.target.value)} />
      </FormField>
      <FormField label={t("organizations.form.displayName")} hint={t("organizations.form.displayName.hint")}>
        <Input value={displayName} placeholder="Acme Inc" onChange={(e) => setDisplayName(e.target.value)} />
      </FormField>
      <FormField label={t("organizations.form.domains")} hint={t("organizations.form.domains.hint")} error={errors.domains}>
        <Input value={domainsText} placeholder="acme.com, acme.io" onChange={(e) => setDomainsText(e.target.value)} />
      </FormField>
      <Switch checked={enabled} onChange={setEnabled} label={t("organizations.form.enabled")} />
      <div className="hx-formactions">
        <Button variant="ghost" onClick={onCancel}>{t("common.cancel")}</Button>
        <Button variant="primary" onClick={save}>{initial ? t("common.save") : t("organizations.form.create")}</Button>
      </div>
    </div>
  );
}
