-- V3: Reference data — roles, permissions, and the grants between them.
--
-- This is MASTER DATA, not seed data. It ships as a migration because the application
-- cannot function without it in any environment: an empty permissions table means every
-- @RequirePermission check denies. Demo/fixture data belongs somewhere else entirely and
-- must never run outside local development.
--
-- Every statement is ON CONFLICT DO NOTHING so re-running against a database that already
-- has the rows is a no-op rather than a failed migration.
--
-- Roles here are PLATFORM roles and deliberately generic. Legal-domain roles (attorney,
-- paralegal, billing clerk) are organization-scoped and belong to the product, not the
-- platform baseline — they will be granted through user_roles.organization_id.

INSERT INTO roles (id, name, level, description) VALUES
    ('11111111-0000-4000-8000-000000000001', 'SUPER_ADMIN',   30, 'Jurivo platform operator. Bypasses tenant isolation.'),
    ('11111111-0000-4000-8000-000000000002', 'ORG_ADMIN',     20, 'Administrator of one organization: manages its users and settings.'),
    ('11111111-0000-4000-8000-000000000003', 'MEMBER',        10, 'Ordinary member of an organization.'),
    ('11111111-0000-4000-8000-000000000004', 'VIEWER',         0, 'Read-only access within an organization.')
ON CONFLICT (name) DO NOTHING;

INSERT INTO permissions (id, code, description) VALUES
    ('22222222-0000-4000-8000-000000000001', 'ORGANIZATIONS:READ',   'View organizations in scope'),
    ('22222222-0000-4000-8000-000000000002', 'ORGANIZATIONS:CREATE', 'Create an organization'),
    ('22222222-0000-4000-8000-000000000003', 'ORGANIZATIONS:UPDATE', 'Update an organization'),
    ('22222222-0000-4000-8000-000000000004', 'ORGANIZATIONS:DELETE', 'Close an organization'),
    ('22222222-0000-4000-8000-000000000005', 'USERS:READ',           'View users in scope'),
    ('22222222-0000-4000-8000-000000000006', 'USERS:CREATE',         'Invite or create a user'),
    ('22222222-0000-4000-8000-000000000007', 'USERS:UPDATE',         'Update a user'),
    ('22222222-0000-4000-8000-000000000008', 'USERS:DELETE',         'Deactivate a user'),
    ('22222222-0000-4000-8000-000000000009', 'ACCESS_CONTROL:READ',  'View roles and permission grants'),
    ('22222222-0000-4000-8000-00000000000a', 'ACCESS_CONTROL:MANAGE','Grant and revoke roles'),
    ('22222222-0000-4000-8000-00000000000b', 'AUDIT:READ',           'Read entity change history')
ON CONFLICT (code) DO NOTHING;

-- SUPER_ADMIN: everything.
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r CROSS JOIN permissions p
WHERE r.name = 'SUPER_ADMIN'
ON CONFLICT DO NOTHING;

-- ORG_ADMIN: everything except creating and closing organizations, which is a platform
-- operation (a firm cannot mint new tenants for itself).
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r CROSS JOIN permissions p
WHERE r.name = 'ORG_ADMIN'
  AND p.code NOT IN ('ORGANIZATIONS:CREATE', 'ORGANIZATIONS:DELETE')
ON CONFLICT DO NOTHING;

-- MEMBER: read the organization and its people; no access-control or audit surface.
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r CROSS JOIN permissions p
WHERE r.name = 'MEMBER'
  AND p.code IN ('ORGANIZATIONS:READ', 'USERS:READ')
ON CONFLICT DO NOTHING;

-- VIEWER: read the organization only.
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r CROSS JOIN permissions p
WHERE r.name = 'VIEWER'
  AND p.code IN ('ORGANIZATIONS:READ')
ON CONFLICT DO NOTHING;

-- Cognito group -> role mapping. The groups are created by jurivo-cdk on the user pool;
-- the names must match exactly. A group with no mapping grants nothing, which is the
-- correct failure direction.
INSERT INTO cognito_group_role_mappings (id, cognito_group, role_id)
SELECT '33333333-0000-4000-8000-000000000001', 'jurivo-super-admins', r.id FROM roles r WHERE r.name = 'SUPER_ADMIN'
ON CONFLICT (cognito_group) DO NOTHING;

INSERT INTO cognito_group_role_mappings (id, cognito_group, role_id)
SELECT '33333333-0000-4000-8000-000000000002', 'jurivo-org-admins', r.id FROM roles r WHERE r.name = 'ORG_ADMIN'
ON CONFLICT (cognito_group) DO NOTHING;
