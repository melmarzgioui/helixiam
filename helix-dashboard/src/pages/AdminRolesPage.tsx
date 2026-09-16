/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import React from "react";
import { Page, PageHeader, PageBody } from "../components/Page";
import { Button } from "../components/Button";
import { Switch } from "../components/Switch";
import { Toast, ToastTone } from "../components/Toast";
import { EmptyState } from "../components/EmptyState";
import { Spinner } from "../components/Spinner";
import {
  AdminRoleApi,
  AdminPermission,
  AdminRoleGrants,
  togglePermission,
  effectivelyGrants,
} from "../api/adminRoles";
import { useT } from "../i18n/LocaleContext";

export interface AdminRolesPageProps {
  api: AdminRoleApi;
  realmId: string;
}

interface Note { tone: ToastTone; title: string; message?: string; }

/**
 * Fine-grained admin RBAC — the "Admin roles" permission matrix. Each realm role (row) can be granted a
 * composable set of admin permissions (columns). Holding "Full realm administration" (realm-admin) implies
 * every permission. A realm with no grants behaves as today (any admin is allowed).
 */
export function AdminRolesPage({ api, realmId }: AdminRolesPageProps) {
  const { t } = useT();
  const [permissions, setPermissions] = React.useState<AdminPermission[] | null>(null);
  const [rows, setRows] = React.useState<AdminRoleGrants[] | null>(null);
  const [draft, setDraft] = React.useState<Record<string, string[]>>({});
  const [saving, setSaving] = React.useState<string | null>(null);
  const [note, setNote] = React.useState<Note | null>(null);

  const reload = React.useCallback(() => {
    setRows(null);
    Promise.all([api.permissions(realmId), api.roles(realmId)])
      .then(([perms, roles]) => {
        setPermissions(perms);
        setRows(roles);
        setDraft(Object.fromEntries(roles.map((r) => [r.roleId, [...r.permissions]])));
      })
      .catch((e) => {
        setRows([]);
        setNote({ tone: "error", title: t("adminRoles.error.load"), message: String(e.message ?? e) });
      });
  }, [api, realmId, t]);

  React.useEffect(reload, [reload]);

  const onToggle = (roleId: string, key: string) => {
    setDraft((d) => ({ ...d, [roleId]: togglePermission(d[roleId] ?? [], key) }));
  };

  const isDirty = (roleId: string): boolean => {
    const row = rows?.find((r) => r.roleId === roleId);
    const a = [...(row?.permissions ?? [])].sort();
    const b = [...(draft[roleId] ?? [])].sort();
    return a.length !== b.length || a.some((v, i) => v !== b[i]);
  };

  const save = async (roleId: string, roleName: string) => {
    setSaving(roleId);
    try {
      const saved = await api.setPermissions(realmId, roleId, draft[roleId] ?? []);
      setRows((rs) => (rs ?? []).map((r) => (r.roleId === roleId ? saved : r)));
      setDraft((d) => ({ ...d, [roleId]: [...saved.permissions] }));
      setNote({ tone: "success", title: t("adminRoles.perms.saved.title"), message: t("adminRoles.perms.saved.msg", { name: roleName }) });
    } catch (e: unknown) {
      setNote({ tone: "error", title: t("adminRoles.error.save"), message: String((e as Error).message ?? e) });
    } finally {
      setSaving(null);
    }
  };

  return (
    <Page>
      <PageHeader
        title={t("adminRoles.title")}
        description={<>{t("adminRoles.description.pre")}<strong>{realmId}</strong>{t("adminRoles.description.post")}</>}
        actions={<Button variant="ghost" onClick={reload}>{t("adminRoles.action.refresh")}</Button>}
      />

      <PageBody>
      {rows === null || permissions === null ? (
        <div className="hx-loadwrap">
          <Spinner size={28} label={t("adminRoles.loading")} />
        </div>
      ) : rows.length === 0 ? (
        <EmptyState
          title={t("adminRoles.empty.title")}
          message={t("adminRoles.empty.msg")}
        />
      ) : (
        <div className="hx-card">
          <div className="hx-tablescroll">
            <table className="hx-table" data-testid="admin-rbac-matrix">
              <thead>
                <tr>
                  <th className="hx-col-sticky">{t("adminRoles.col.role")}</th>
                  {permissions.map((p) => (
                    <th key={p.key} title={p.label} className="hx-nowrap">{p.label}</th>
                  ))}
                  <th className="hx-col-actions" aria-label={t("adminRoles.col.actions")} />
                </tr>
              </thead>
              <tbody>
                {rows.map((r) => {
                  const grants = draft[r.roleId] ?? [];
                  const realmAdmin = grants.includes("realm-admin");
                  return (
                    <tr key={r.roleId} data-testid={`admin-rbac-row-${r.roleName}`}>
                      <td className="hx-col-sticky hx-cell-strong">{r.roleName}</td>
                      {permissions.map((p) => {
                        // realm-admin implies all others — show them ON + locked when realm-admin is held.
                        const impliedByRealmAdmin = realmAdmin && p.key !== "realm-admin";
                        return (
                          <td key={p.key} className="hx-cell-center"
                              title={`${p.label} — ${r.roleName}`}
                              data-testid={`cell-${r.roleName}-${p.key}`}>
                            <Switch
                              checked={impliedByRealmAdmin ? true : effectivelyGrants(grants, p.key)}
                              disabled={impliedByRealmAdmin}
                              onChange={() => onToggle(r.roleId, p.key)}
                            />
                          </td>
                        );
                      })}
                      <td className="hx-cell-right">
                        <Button
                          variant="primary"
                          disabled={!isDirty(r.roleId) || saving === r.roleId}
                          onClick={() => save(r.roleId, r.roleName)}
                        >
                          {saving === r.roleId ? t("adminRoles.saving") : t("common.save")}
                        </Button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
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
