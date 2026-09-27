-- Review rc.3 #1 (security): before this release a realm admin could grant a role of ANOTHER realm to a user
-- (e.g. the master realm's admin role, i.e. admin of every realm). A role grant is only valid when the user is a
-- member of the role's own realm; remove every grant that is not.
DELETE FROM user_in_role uir
 WHERE NOT EXISTS (SELECT 1 FROM user_roles r
                     JOIN tenant_user tu ON tu.tenant_id = r.tenant_id
                    WHERE r.role_id = uir.role_id AND tu.user_id = uir.user_id);
