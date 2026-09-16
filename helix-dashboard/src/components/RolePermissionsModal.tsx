import React from "react";
import { Modal } from "./Modal";
import { Button } from "./Button";
import { Switch } from "./Switch";
import { Spinner } from "./Spinner";
import {
  AdminRoleApi,
  AdminPermission,
  togglePermission,
  effectivelyGrants,
} from "../api/adminRoles";

export interface RolePermissionsModalProps {
  open: boolean;
  api: AdminRoleApi;
  realmId: string;
  roleId: string;
  roleName: string;
  onClose: () => void;
  onSaved?: (permissions: string[]) => void;
}

/**
 * Keycloak / WSO2-IS-style "role permissions" dialog: open a role, edit the fine-grained admin permissions it
 * grants. Reuses the admin-RBAC catalogue + the same "realm-admin implies (and locks) every permission" rule as
 * the Admin roles matrix — this is the per-role entry point into the same model.
 */
export function RolePermissionsModal({ open, api, realmId, roleId, roleName, onClose, onSaved }: RolePermissionsModalProps) {
  const [catalog, setCatalog] = React.useState<AdminPermission[] | null>(null);
  const [draft, setDraft] = React.useState<string[]>([]);
  const [initial, setInitial] = React.useState<string[]>([]);
  const [saving, setSaving] = React.useState(false);
  const [error, setError] = React.useState<string | null>(null);

  React.useEffect(() => {
    if (!open) return;
    setCatalog(null);
    setError(null);
    Promise.all([api.permissions(realmId), api.roles(realmId)])
      .then(([perms, roles]) => {
        const grants = roles.find((r) => r.roleId === roleId)?.permissions ?? [];
        setCatalog(perms);
        setDraft([...grants]);
        setInitial([...grants]);
      })
      .catch((e) => setError(String(e.message ?? e)));
  }, [open, api, realmId, roleId]);

  const dirty = React.useMemo(() => {
    const a = [...initial].sort();
    const b = [...draft].sort();
    return a.length !== b.length || a.some((v, i) => v !== b[i]);
  }, [initial, draft]);

  const realmAdmin = draft.includes("realm-admin");

  const save = async () => {
    setSaving(true);
    setError(null);
    try {
      const saved = await api.setPermissions(realmId, roleId, draft);
      setInitial([...saved.permissions]);
      setDraft([...saved.permissions]);
      onSaved?.(saved.permissions);
      onClose();
    } catch (e: unknown) {
      setError(String((e as Error).message ?? e));
    } finally {
      setSaving(false);
    }
  };

  return (
    <Modal
      open={open}
      title={`Permissions — ${roleName}`}
      onClose={onClose}
      width={520}
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>Cancel</Button>
          <Button variant="primary" disabled={!dirty || saving} onClick={save}>
            {saving ? "Saving…" : "Save permissions"}
          </Button>
        </>
      }
    >
      <p className="hx-modal__lede">
        Grant fine-grained admin permissions to <strong>{roleName}</strong>. Users holding this role get exactly
        this scoped admin access. <strong>Full realm administration</strong> implies every permission.
      </p>

      {error && <div className="hx-alert hx-alert--danger" role="alert">{error}</div>}

      {catalog === null ? (
        <div className="hx-loadwrap">
          <Spinner size={24} label="Loading permissions…" />
        </div>
      ) : (
        <div className="hx-togglelist" data-testid="role-permissions-list">
          {catalog.map((p) => {
            const impliedByRealmAdmin = realmAdmin && p.key !== "realm-admin";
            return (
              <div className="hx-togglerow" key={p.key} data-testid={`perm-${p.key}`}>
                <span className="hx-togglerow__label">{p.label}</span>
                <Switch
                  ariaLabel={p.label}
                  checked={impliedByRealmAdmin ? true : effectivelyGrants(draft, p.key)}
                  disabled={impliedByRealmAdmin || saving}
                  onChange={() => setDraft((d) => togglePermission(d, p.key))}
                />
              </div>
            );
          })}
        </div>
      )}
    </Modal>
  );
}
