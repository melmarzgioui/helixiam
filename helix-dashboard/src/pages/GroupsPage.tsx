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
import { FormField, Input, Select } from "../components/FormField";
import { GroupApi, Group, GroupMember, GroupRole } from "../api/groups";
import { UserApi, UserSummary } from "../api/users";
import { RoleApi, Role } from "../api/roles";
import { useT } from "../i18n/LocaleContext";

export interface GroupsPageProps {
  api: GroupApi;
  userApi: UserApi;
  roleApi: RoleApi;
  realmId: string;
}

interface Note { tone: ToastTone; title: string; message?: string; }

/** E8.5-S4: the live Groups screen — hierarchical groups, membership and group→role mappings. */
export function GroupsPage({ api, userApi, roleApi, realmId }: GroupsPageProps) {
  const { t } = useT();
  const [groups, setGroups] = React.useState<Group[] | null>(null);
  const [selectedId, setSelectedId] = React.useState<string | null>(null);
  const [creating, setCreating] = React.useState<{ parentId: string | null } | null>(null);
  const [renaming, setRenaming] = React.useState<Group | null>(null);
  const [toDelete, setToDelete] = React.useState<Group | null>(null);
  const [note, setNote] = React.useState<Note | null>(null);

  const reload = React.useCallback(() => {
    setGroups(null);
    api.list(realmId).then((gs) => {
      setGroups(gs);
      setSelectedId((cur) => (cur && gs.some((g) => g.groupId === cur) ? cur : gs[0]?.groupId ?? null));
    }).catch((e) => {
      setGroups([]);
      setNote({ tone: "error", title: t("groups.load.error"), message: String(e.message ?? e) });
    });
  }, [api, realmId, t]);

  React.useEffect(reload, [reload]);

  const selected = groups?.find((g) => g.groupId === selectedId) ?? null;

  const submitCreate = async (name: string, parentId: string | null) => {
    try {
      const g = await api.create(realmId, name, parentId);
      setCreating(null);
      setNote({ tone: "success", title: t("groups.created"), message: t("groups.created.msg", { name }) });
      reload();
      setSelectedId(g.groupId);
    } catch (e: unknown) {
      setNote({ tone: "error", title: t("groups.create.error"), message: String((e as Error).message ?? e) });
    }
  };

  const submitRename = async (group: Group, name: string) => {
    try {
      await api.rename(realmId, group.groupId, name, group.parentId);
      setRenaming(null);
      reload();
    } catch (e: unknown) {
      setNote({ tone: "error", title: t("groups.rename.error"), message: String((e as Error).message ?? e) });
    }
  };

  const confirmDelete = async () => {
    if (!toDelete) return;
    const target = toDelete;
    setToDelete(null);
    try {
      await api.remove(realmId, target.groupId);
      setNote({ tone: "info", title: t("groups.deleted"), message: t("groups.deleted.msg", { name: target.name }) });
      reload();
    } catch (e: unknown) {
      setNote({ tone: "error", title: t("groups.delete.error"), message: String((e as Error).message ?? e) });
    }
  };

  return (
    <Page>
      <PageHeader
        title={t("groups.title")}
        description={t("groups.description", { realm: realmId })}
        actions={<Button variant="primary" onClick={() => setCreating({ parentId: null })}>{t("groups.new")}</Button>}
      />

      <PageBody>
        {groups === null ? (
          <div className="hx-loadwrap">
            <Spinner size={28} label={t("groups.loading")} />
          </div>
        ) : groups.length === 0 ? (
          <EmptyState
            title={t("groups.empty.title")}
            message={t("groups.empty.msg")}
            action={<Button variant="primary" onClick={() => setCreating({ parentId: null })}>{t("groups.new")}</Button>}
          />
        ) : (
          <div className="hx-detailgrid">
            <Card>
              <GroupTree
                groups={groups}
                parentId={null}
                depth={0}
                selectedId={selectedId}
                onSelect={setSelectedId}
                onAddChild={(parentId) => setCreating({ parentId })}
                onRename={setRenaming}
                onDelete={setToDelete}
              />
            </Card>

            {selected ? (
              <GroupDetail
                key={selected.groupId}
                api={api}
                userApi={userApi}
                roleApi={roleApi}
                realmId={realmId}
                group={selected}
                onChanged={reload}
                onError={(m) => setNote({ tone: "error", title: t("groups.actionFailed"), message: m })}
              />
            ) : (
              <Card><p className="hx-muted">{t("groups.select.hint")}</p></Card>
            )}
          </div>
        )}
      </PageBody>

      <Modal open={creating !== null} title={creating?.parentId ? t("groups.modal.subgroup") : t("groups.modal.new")} onClose={() => setCreating(null)} width={460}>
        {creating && <NameForm placeholder="Civil servants" submitLabel={t("groups.form.submit")} onSubmit={(name) => submitCreate(name, creating.parentId)} onCancel={() => setCreating(null)} />}
      </Modal>
      <Modal open={renaming !== null} title={t("groups.modal.rename")} onClose={() => setRenaming(null)} width={460}>
        {renaming && <NameForm initial={renaming.name} submitLabel={t("common.save")} onSubmit={(name) => submitRename(renaming, name)} onCancel={() => setRenaming(null)} />}
      </Modal>

      <ConfirmDialog
        open={toDelete !== null}
        title={t("groups.confirm.delete.title")}
        message={t("groups.confirm.delete.msg", { name: toDelete?.name ?? "" })}
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

function GroupTree({ groups, parentId, depth, selectedId, onSelect, onAddChild, onRename, onDelete }: {
  groups: Group[]; parentId: string | null; depth: number; selectedId: string | null;
  onSelect: (id: string) => void; onAddChild: (parentId: string) => void;
  onRename: (g: Group) => void; onDelete: (g: Group) => void;
}) {
  const { t } = useT();
  const here = groups.filter((g) => (g.parentId ?? null) === parentId).sort((a, b) => a.name.localeCompare(b.name));
  if (here.length === 0) return null;
  return (
    <>
      {here.map((g) => {
        const active = g.groupId === selectedId;
        return (
          <React.Fragment key={g.groupId}>
            <div
              className={`${active ? "hx-navitem hx-navitem--active" : "hx-navitem"}${depth > 0 ? " hx-tree-row" : ""}`}
              onClick={() => onSelect(g.groupId)}
              style={depth > 0 ? { ["--depth" as never]: depth } : undefined}
            >
              <span className="hx-navitem__icon">
                <svg width="15" height="15" viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="M3 7h6l2 2h10v9a1 1 0 01-1 1H4a1 1 0 01-1-1V7z" stroke="currentColor" strokeWidth="1.7" strokeLinejoin="round" /></svg>
              </span>
              <span className="hx-navitem__grow">{g.name}</span>
              {g.memberCount > 0 && <Badge tone="neutral">{g.memberCount}</Badge>}
              <span onClick={(e) => e.stopPropagation()}>
                <RowMenu ariaLabel={t("groups.row.actions", { name: g.name })} items={[
                  { label: t("groups.row.addSubgroup"), onSelect: () => onAddChild(g.groupId) },
                  { label: t("groups.row.rename"), onSelect: () => onRename(g) },
                  { label: t("groups.row.delete"), danger: true, onSelect: () => onDelete(g) },
                ]} />
              </span>
            </div>
            <GroupTree groups={groups} parentId={g.groupId} depth={depth + 1} selectedId={selectedId} onSelect={onSelect} onAddChild={onAddChild} onRename={onRename} onDelete={onDelete} />
          </React.Fragment>
        );
      })}
    </>
  );
}

function GroupDetail({ api, userApi, roleApi, realmId, group, onChanged, onError }: {
  api: GroupApi; userApi: UserApi; roleApi: RoleApi; realmId: string; group: Group;
  onChanged: () => void; onError: (m: string) => void;
}) {
  const { t } = useT();
  const [members, setMembers] = React.useState<GroupMember[] | null>(null);
  const [roles, setRoles] = React.useState<GroupRole[] | null>(null);
  const [allUsers, setAllUsers] = React.useState<UserSummary[]>([]);
  const [allRoles, setAllRoles] = React.useState<Role[]>([]);
  const [addUser, setAddUser] = React.useState("");
  const [addRole, setAddRole] = React.useState("");

  const load = React.useCallback(() => {
    api.members(realmId, group.groupId).then(setMembers).catch((e) => onError(String(e.message ?? e)));
    api.roles(realmId, group.groupId).then(setRoles).catch((e) => onError(String(e.message ?? e)));
  }, [api, realmId, group.groupId, onError]);

  React.useEffect(() => {
    load();
    userApi.list(realmId).then(setAllUsers).catch(() => undefined);
    roleApi.list(realmId).then(setAllRoles).catch(() => undefined);
  }, [load, userApi, roleApi, realmId]);

  const candidates = allUsers.filter((u) => !(members ?? []).some((m) => m.userId === u.userId));
  const roleCandidates = allRoles.filter((r) => !(roles ?? []).some((gr) => gr.roleId === r.roleId));

  const wrap = (p: Promise<unknown>) => p.then(() => { load(); onChanged(); }).catch((e: Error) => onError(String(e.message ?? e)));

  return (
    <Section title={group.name}>
      <div className="hx-pagebody">
        <div>
          <div className="hx-when-label">{t("groups.detail.members")}</div>
          {members === null ? (
            <Spinner size={20} label={t("common.loading")} />
          ) : members.length === 0 ? (
            <p className="hx-faint">{t("groups.detail.noMembers")}</p>
          ) : (
            <div className="hx-togglelist">
              {members.map((m) => (
                <div className="hx-togglerow" key={m.userId}>
                  <span className="hx-togglerow__label">{m.username}</span>
                  <Button variant="ghost" onClick={() => wrap(api.removeMember(realmId, group.groupId, m.userId))}>{t("groups.detail.remove")}</Button>
                </div>
              ))}
            </div>
          )}
          <div className="hx-toolbar">
            <div className="hx-toolbar__grow">
              <Select
                options={[{ value: "", label: candidates.length ? t("groups.detail.addUser") : t("groups.detail.allMembers") }, ...candidates.map((u) => ({ value: u.userId, label: u.username }))]}
                value={addUser} onChange={setAddUser} aria-label={t("groups.detail.addMember.aria")}
              />
            </div>
            <Button variant="primary" disabled={!addUser} onClick={() => { wrap(api.addMember(realmId, group.groupId, addUser)); setAddUser(""); }}>{t("groups.detail.add")}</Button>
          </div>
        </div>

        <div>
          <div className="hx-when-label">{t("groups.detail.roleMappings")}</div>
          <p className="hx-help">{t("groups.detail.roleMappings.hint")}</p>
          {roles === null ? (
            <Spinner size={20} label={t("common.loading")} />
          ) : roles.length === 0 ? (
            <p className="hx-faint">{t("groups.detail.noRoles")}</p>
          ) : (
            <div className="hx-badges">
              {roles.map((r) => (
                <span key={r.roleId} className="hx-chip">
                  {r.name}
                  <button type="button" className="hx-chip__x" aria-label={t("groups.detail.removeRole.aria", { name: r.name })} onClick={() => wrap(api.unassignRole(realmId, group.groupId, r.roleId))}>
                    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="M6 6l12 12M18 6L6 18" stroke="currentColor" strokeWidth="2.4" strokeLinecap="round" /></svg>
                  </button>
                </span>
              ))}
            </div>
          )}
          <div className="hx-toolbar">
            <div className="hx-toolbar__grow">
              <Select
                options={[{ value: "", label: roleCandidates.length ? t("groups.detail.mapRole") : t("groups.detail.allRoles") }, ...roleCandidates.map((r) => ({ value: r.roleId, label: r.name }))]}
                value={addRole} onChange={setAddRole} aria-label={t("groups.detail.mapRole.aria")}
              />
            </div>
            <Button variant="primary" disabled={!addRole} onClick={() => { wrap(api.assignRole(realmId, group.groupId, addRole)); setAddRole(""); }}>{t("groups.detail.map")}</Button>
          </div>
        </div>
      </div>
    </Section>
  );
}

function NameForm({ initial = "", placeholder, submitLabel, onSubmit, onCancel }: {
  initial?: string; placeholder?: string; submitLabel: string; onSubmit: (name: string) => void; onCancel: () => void;
}) {
  const { t } = useT();
  const [name, setName] = React.useState(initial);
  const [attempted, setAttempted] = React.useState(false);
  const missing = !name.trim();
  const save = () => { if (missing) { setAttempted(true); return; } onSubmit(name.trim()); };
  return (
    <div>
      <FormField label={t("groups.form.name")} required error={attempted && missing ? t("groups.form.name.required") : undefined}>
        <Input value={name} autoFocus placeholder={placeholder} onChange={(e) => setName(e.target.value)} onKeyDown={(e) => e.key === "Enter" && save()} />
      </FormField>
      <div className="hx-formactions">
        <Button variant="ghost" onClick={onCancel}>{t("common.cancel")}</Button>
        <Button variant="primary" onClick={save}>{submitLabel}</Button>
      </div>
    </div>
  );
}
