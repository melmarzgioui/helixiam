/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import React from "react";
import { Page, PageHeader, PageBody } from "../components/Page";
import { Button } from "../components/Button";
import { Modal, ConfirmDialog } from "../components/Modal";
import { Toast, ToastTone } from "../components/Toast";
import { EmptyState } from "../components/EmptyState";
import { Spinner } from "../components/Spinner";
import { FormField, Input } from "../components/FormField";
import { RowMenu } from "../components/RowMenu";
import { Badge } from "../components/Badge";
import { RolePermissionsModal } from "../components/RolePermissionsModal";
import { RoleApi, Role } from "../api/roles";
import { AdminRoleApi } from "../api/adminRoles";
import { useT } from "../i18n/LocaleContext";

export interface RolesPageProps {
  api: RoleApi;
  adminApi: AdminRoleApi;
  realmId: string;
}

interface Note { tone: ToastTone; title: string; message?: string; }

/** E8.5-S2 / DR: the live Realm roles screen — roles admin API + per-role admin-permission editor. */
export function RolesPage({ api, adminApi, realmId }: RolesPageProps) {
  const { t } = useT();
  const [rows, setRows] = React.useState<Role[] | null>(null);
  const [creating, setCreating] = React.useState(false);
  const [toDelete, setToDelete] = React.useState<Role | null>(null);
  const [perms, setPerms] = React.useState<Role | null>(null);
  const [note, setNote] = React.useState<Note | null>(null);

  const reload = React.useCallback(() => {
    setRows(null);
    api.list(realmId).then(setRows).catch((e) => {
      setRows([]);
      setNote({ tone: "error", title: t("roles.error.load"), message: String(e.message ?? e) });
    });
  }, [api, realmId, t]);

  React.useEffect(reload, [reload]);

  const submitCreate = async (name: string) => {
    try {
      await api.create(realmId, name);
      setCreating(false);
      setNote({ tone: "success", title: t("roles.created.title"), message: t("roles.created.msg", { name, realm: realmId }) });
      reload();
    } catch (e: unknown) {
      setNote({ tone: "error", title: t("roles.error.create"), message: String((e as Error).message ?? e) });
    }
  };

  const confirmDelete = async () => {
    if (!toDelete) return;
    const target = toDelete;
    setToDelete(null);
    try {
      await api.remove(realmId, target.roleId);
      setNote({ tone: "info", title: t("roles.deleted.title"), message: t("roles.deleted.msg", { name: target.name }) });
      reload();
    } catch (e: unknown) {
      setNote({ tone: "error", title: t("roles.error.delete"), message: String((e as Error).message ?? e) });
    }
  };

  const setDefault = async (role: Role) => {
    try {
      await api.setDefault(realmId, role.roleId);
      setNote({ tone: "success", title: t("roles.default.title"), message: t("roles.default.msg", { realm: realmId, name: role.name }) });
      reload();
    } catch (e: unknown) {
      setNote({ tone: "error", title: t("roles.error.setDefault"), message: String((e as Error).message ?? e) });
    }
  };

  const menuItems = (r: Role) => {
    const items = [
      { label: t("roles.menu.permissions"), onSelect: () => setPerms(r) },
    ];
    if (!r.defaultRole) items.push({ label: t("roles.menu.setDefault"), onSelect: () => setDefault(r) });
    // System roles (admin/user/auditor) are protected — no delete.
    if (!r.system) items.push({ label: t("roles.menu.delete"), danger: true, onSelect: () => setToDelete(r) } as typeof items[number]);
    return items;
  };

  const roleBadges = (r: Role) => (
    <span className="hx-badges">
      {r.system && <Badge tone="neutral">{t("roles.badge.system")}</Badge>}
      {r.defaultRole && <Badge tone="accent">{t("roles.badge.default")}</Badge>}
    </span>
  );

  return (
    <Page>
      <PageHeader
        title={t("roles.title")}
        description={<>{t("roles.description.pre")}<strong>{realmId}</strong>{t("roles.description.post")}</>}
        actions={<Button variant="primary" onClick={() => setCreating(true)}>{t("roles.action.create")}</Button>}
      />

      <PageBody>
      {rows === null ? (
        <div className="hx-loadwrap">
          <Spinner size={28} label={t("roles.loading")} />
        </div>
      ) : rows.length === 0 ? (
        <EmptyState
          title={t("roles.empty.title")}
          message={t("roles.empty.msg")}
          action={<Button variant="primary" onClick={() => setCreating(true)}>{t("roles.action.create")}</Button>}
        />
      ) : (
        <>
          {/* desktop table */}
          <div className="hx-card hx-show-desktop">
            <div className="hx-tablescroll">
              <table className="hx-table">
                <thead>
                  <tr><th>{t("roles.col.name")}</th><th>{t("roles.col.id")}</th><th className="hx-col-actions" aria-label={t("roles.col.actions")} /></tr>
                </thead>
                <tbody>
                  {rows.map((r) => (
                    <tr key={r.roleId}>
                      <td>
                        <div className="hx-namecell">
                          <button type="button" className="hx-textbtn" onClick={() => setPerms(r)}>{r.name}</button>
                          {roleBadges(r)}
                        </div>
                      </td>
                      <td><span className="hx-conn__alias">{r.roleId.slice(0, 8)}</span></td>
                      <td className="hx-cell-right">
                        <RowMenu items={menuItems(r)} />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* mobile cards */}
          <div className="hx-cards hx-show-mobile">
            {rows.map((r) => (
              <div className="hx-rowcard" key={r.roleId}>
                <div className="hx-rowcard__head">
                  <div className="hx-rowcard__grow">
                    <div className="hx-rowcard__title hx-namecell">
                      {r.name}{roleBadges(r)}
                    </div>
                    <div className="hx-rowcard__sub hx-mono">{r.roleId.slice(0, 8)}</div>
                  </div>
                  <div className="hx-rowcard__actions">
                    <RowMenu items={menuItems(r)} />
                  </div>
                </div>
              </div>
            ))}
          </div>
        </>
      )}
      </PageBody>

      <Modal open={creating} title={t("roles.modal.create.title")} onClose={() => setCreating(false)} width={440}>
        <RoleForm onSubmit={submitCreate} onCancel={() => setCreating(false)} />
      </Modal>

      {perms && (
        <RolePermissionsModal
          open={perms !== null}
          api={adminApi}
          realmId={realmId}
          roleId={perms.roleId}
          roleName={perms.name}
          onClose={() => setPerms(null)}
          onSaved={() => setNote({ tone: "success", title: t("roles.perms.saved.title"), message: t("roles.perms.saved.msg", { name: perms.name }) })}
        />
      )}

      <ConfirmDialog
        open={toDelete !== null}
        title={t("roles.confirm.delete.title")}
        message={t("roles.confirm.delete.msg", { name: toDelete?.name ?? "" })}
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

function RoleForm({ onSubmit, onCancel }: { onSubmit: (name: string) => void; onCancel: () => void }) {
  const { t } = useT();
  const [name, setName] = React.useState("");
  const [attempted, setAttempted] = React.useState(false);
  const save = () => { if (!name.trim()) { setAttempted(true); return; } onSubmit(name.trim()); };
  return (
    <div>
      <FormField label={t("roles.form.name.label")} required error={attempted && !name.trim() ? t("roles.form.name.required") : undefined} hint={t("roles.form.name.hint")}>
        <Input value={name} onChange={(e) => setName(e.target.value)} placeholder={t("roles.form.name.placeholder")} />
      </FormField>
      <div className="hx-formactions">
        <Button variant="ghost" onClick={onCancel}>{t("common.cancel")}</Button>
        <Button variant="primary" onClick={save}>{t("roles.action.create")}</Button>
      </div>
    </div>
  );
}
