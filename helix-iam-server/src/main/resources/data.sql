-- insert or REPLACE  into user (role_id, name, owner_id, description) values ('1', 'ROLE_ADMIN', null, 'Admin voor de organisatie');

insert into tenant (tenant_id, name) values ('-1234', 'KubeDNA')
ON CONFLICT (tenant_id) DO UPDATE
    SET name = excluded.name;

insert into user_roles (role_id, name, description, tenant_id) values ('1', 'ROLE_ADMIN', 'Super admin', '-1234')
ON CONFLICT (role_id) DO UPDATE
    SET name = excluded.name,
        tenant_id = excluded.tenant_id,
        description = excluded.description;
-- insert or REPLACE into user_in_role (role_id, user_id) values ("1", "12345");