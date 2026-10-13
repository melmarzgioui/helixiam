-- Copyright 2026 HelixIAM contributors
-- SPDX-License-Identifier: Apache-2.0
--
-- Before upgrading to the Spring Boot 4 release (docs/UPGRADING.md): lists every role whose name is in the FACTOR_
-- namespace, which the release reserves for Spring Security 7's sign-in factors (FACTOR_PASSWORD on every password
-- login). From the upgrade on such a role is ignored: never a role in admin RBAC, never in a token. An empty result
-- means there is nothing to do; otherwise rename the role (create the new name, move its users, grants and mappings,
-- delete the old one) before upgrading.
--
--   psql "$DATABASE_URL" -f deploy/scripts/factor-roles-check.sql
SELECT 'realm role' AS kind, tenant_id AS realm, name AS role, NULL AS holder
  FROM user_roles WHERE name ILIKE 'factor\_%'
UNION ALL
SELECT 'client role', realm_id, name, client_id
  FROM client_role WHERE name ILIKE 'factor\_%'
UNION ALL
SELECT 'service-account role', realm_id, role_name, client_id
  FROM client_service_account_role WHERE role_name ILIKE 'factor\_%'
UNION ALL
SELECT 'agent role', realm_id, roles, name
  FROM agent_identity WHERE roles ~* '(^|[,[:space:]/])factor_'
ORDER BY 1, 2, 3;
