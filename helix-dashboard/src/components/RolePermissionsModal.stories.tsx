import type { Meta, StoryObj } from "@storybook/react";
import React from "react";
import { RolePermissionsModal } from "./RolePermissionsModal";
import { Button } from "./Button";
import { createAdminRoleMemoryClient, AdminPermission, AdminRoleGrants } from "../api/adminRoles";

const CATALOG: AdminPermission[] = [
  { key: "realm-admin", label: "Full realm administration" },
  { key: "view-users", label: "View users" },
  { key: "manage-users", label: "Manage users" },
  { key: "view-clients", label: "View clients" },
  { key: "manage-clients", label: "Manage clients" },
  { key: "manage-roles", label: "Manage roles" },
  { key: "manage-identity-providers", label: "Manage identity providers" },
  { key: "manage-authorization", label: "Manage authorization" },
  { key: "manage-organizations", label: "Manage organizations" },
  { key: "manage-realm", label: "Manage realm" },
  { key: "view-events", label: "View events" },
  { key: "manage-events", label: "Manage events" },
];

const GRANTS: AdminRoleGrants[] = [
  { realmId: "acme", roleId: "r-admin", roleName: "admin", permissions: ["realm-admin"] },
  { realmId: "acme", roleId: "r-auditor", roleName: "auditor", permissions: ["view-users", "view-clients", "view-events"] },
];

const meta: Meta = { title: "Roles/RolePermissionsModal" };
export default meta;
type Story = StoryObj;

/** Auditor role — a scoped, read-only set of admin permissions. */
export const Auditor: Story = {
  render: () => {
    const api = createAdminRoleMemoryClient(CATALOG, GRANTS);
    const [open, setOpen] = React.useState(true);
    return (
      <>
        <Button onClick={() => setOpen(true)}>Permissions…</Button>
        <RolePermissionsModal open={open} api={api} realmId="acme" roleId="r-auditor" roleName="auditor" onClose={() => setOpen(false)} />
      </>
    );
  },
};

/** Admin role — holds realm-admin, so every other permission shows ON and locked. */
export const FullRealmAdmin: Story = {
  render: () => {
    const api = createAdminRoleMemoryClient(CATALOG, GRANTS);
    const [open, setOpen] = React.useState(true);
    return (
      <>
        <Button onClick={() => setOpen(true)}>Permissions…</Button>
        <RolePermissionsModal open={open} api={api} realmId="acme" roleId="r-admin" roleName="admin" onClose={() => setOpen(false)} />
      </>
    );
  },
};
