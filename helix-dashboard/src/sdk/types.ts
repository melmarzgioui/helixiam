/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * Hand-written types mirroring the Helix IAM Admin API OpenAPI shape (group "admin").
 *
 * These are a small, representative subset — enough to demonstrate the SDK story. They are
 * intended to be REPLACED by types generated from the live spec at `/v3/api-docs/admin`
 * (see README.md for the openapi-typescript / openapi-generator instructions).
 */

/** A realm user (UserAdminDto). Passwords are write-only and never returned. */
export interface User {
  realmId: string;
  userId: string;
  username: string;
  email: string | null;
  enabled: boolean;
  locked: boolean;
  mfaEnabled: boolean;
  roles: string[];
  attributes: Record<string, string>;
  createdAt: number | null;
}

/** Create/update body for a user (UserAdminRequest). `password` is only honoured on create. */
export interface UserWrite {
  username: string;
  email?: string;
  password?: string;
  enabled: boolean;
  locked?: boolean;
  attributes?: Record<string, string>;
}

/** A realm role (RoleDto). */
export interface Role {
  realmId: string;
  roleId: string;
  name: string;
}

/** A B2B organization (OrgDto). */
export interface Organization {
  realmId: string;
  orgId: string;
  name: string;
  displayName: string | null;
  domains: string[];
  enabled: boolean;
}

/** Create/update body for an organization (OrgRequest). */
export interface OrganizationWrite {
  name: string;
  displayName?: string;
  domains?: string[];
  enabled?: boolean;
}
