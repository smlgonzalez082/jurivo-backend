-- V4: User and role management.
--
-- Two changes, one of which is a security boundary:
--
-- 1. Roles become organization-scoped. A firm can define "Paralegal" with its own permission
--    set. System roles (organization_id IS NULL, is_system TRUE) stay platform-owned and
--    immutable.
--
-- 2. Because two firms can now each have a role named "Paralegal", ROLE NAMES ARE NO LONGER
--    UNIQUE. Anything resolving permissions by name is now wrong, and wrong in the worst
--    direction — it would union two unrelated firms' grants. Resolution moves to role IDs.
--
-- The escalation this opens, and how it is closed: a firm could create a custom role literally
-- named 'SUPER_ADMIN'. If role checks matched on name, that would grant platform-operator
-- powers to anyone the firm assigned it to. Three independent defences:
--   a. The CHECK constraint below rejects reserved names at the database.
--   b. RoleService rejects them again, case-insensitively, with a clear message.
--   c. UserPrincipal keeps system roles in a separate set, and only that set satisfies
--      @RequireRole or grants tenant-isolation bypass. A custom role can only ever contribute
--      permissions.
-- Any one of the three would do. All three are cheap.

-- ============================================================================
-- 1. Roles gain an owner and a system flag
-- ============================================================================
ALTER TABLE roles ADD COLUMN organization_id UUID REFERENCES organizations (id) ON DELETE CASCADE;
ALTER TABLE roles ADD COLUMN is_system BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE roles ADD COLUMN updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();

-- Everything seeded by V3 is a platform role.
UPDATE roles SET is_system = TRUE WHERE organization_id IS NULL;

-- A system role must have no owner, and an owned role must not claim to be a system role.
-- Without this, a single UPDATE could turn a firm's custom role into a platform one.
ALTER TABLE roles ADD CONSTRAINT roles_system_has_no_owner_check
    CHECK ((is_system AND organization_id IS NULL) OR (NOT is_system));

-- Names are unique per owner now, not globally. NULLS NOT DISTINCT is load-bearing: with
-- default NULL semantics this permits unlimited duplicate platform roles.
ALTER TABLE roles DROP CONSTRAINT roles_name_key;
ALTER TABLE roles ADD CONSTRAINT roles_name_organization_key
    UNIQUE NULLS NOT DISTINCT (name, organization_id);

-- Defence (a): reserved names, enforced by the database against every writer including a psql
-- session. Compared case-insensitively because 'super_admin' would otherwise slip through and
-- any future case-insensitive comparison would then match it.
ALTER TABLE roles ADD CONSTRAINT roles_reserved_names_check
    CHECK (
        is_system
        OR UPPER(name) NOT IN ('SUPER_ADMIN', 'ORG_ADMIN', 'MEMBER', 'VIEWER', 'SYSTEM')
    );

CREATE INDEX idx_roles_organization_id ON roles (organization_id);

-- ============================================================================
-- 2. Users gain their Cognito username
--
-- The pool is configured with email as the sign-in attribute, so Cognito's username IS the
-- email address and is immutable — changing a user's email means a new Cognito account, not an
-- attribute update. Storing it explicitly rather than deriving it from users.email keeps the
-- admin API calls correct if that ever stops being true.
-- ============================================================================
ALTER TABLE users ADD COLUMN cognito_username VARCHAR(320);
ALTER TABLE users_history ADD COLUMN cognito_username VARCHAR(320);

UPDATE users SET cognito_username = email WHERE cognito_username IS NULL;

CREATE INDEX idx_users_cognito_username ON users (cognito_username);

-- The history trigger mirrors every base column, so it has to be replaced whenever one is added.
CREATE OR REPLACE FUNCTION record_users_history() RETURNS TRIGGER AS $$
DECLARE
    v_actor      UUID        := NULLIF(current_setting('app.user_id', true), '')::UUID;
    v_actor_name VARCHAR(255) := NULLIF(current_setting('app.user_name', true), '');
    v_correlation UUID       := NULLIF(current_setting('app.correlation_id', true), '')::UUID;
    v_row        users%ROWTYPE;
BEGIN
    IF TG_OP = 'DELETE' THEN
        v_row := OLD;
    ELSE
        v_row := NEW;
    END IF;

    INSERT INTO users_history (
        user_id, idp_sub, email, full_name, organization_id, status, last_login_at,
        cognito_username, created_at, updated_at, change_type, changed_by, changed_by_name,
        correlation_id
    ) VALUES (
        v_row.id, v_row.idp_sub, v_row.email, v_row.full_name, v_row.organization_id,
        v_row.status, v_row.last_login_at, v_row.cognito_username, v_row.created_at,
        v_row.updated_at, TG_OP, v_actor, v_actor_name, v_correlation
    );

    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- 3. Role change history
--
-- Who granted which permission to which role, and when, is exactly the question an audit asks
-- after an access incident. Roles are now a tenant-editable business entity, so they get the
-- same treatment as every other one.
-- ============================================================================
CREATE TABLE roles_history (
    history_id      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    role_id         UUID        NOT NULL,
    name            VARCHAR(64),
    level           INTEGER,
    description     TEXT,
    organization_id UUID,
    is_system       BOOLEAN,
    created_at      TIMESTAMPTZ,
    updated_at      TIMESTAMPTZ,
    change_type     VARCHAR(10) NOT NULL,
    changed_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    changed_by      UUID,
    changed_by_name VARCHAR(255),
    correlation_id  UUID
);

CREATE INDEX idx_roles_history_role_id ON roles_history (role_id);
CREATE INDEX idx_roles_history_changed_at ON roles_history (changed_at DESC);
CREATE INDEX idx_roles_history_correlation_id ON roles_history (correlation_id);

CREATE OR REPLACE FUNCTION record_roles_history() RETURNS TRIGGER AS $$
DECLARE
    v_actor      UUID        := NULLIF(current_setting('app.user_id', true), '')::UUID;
    v_actor_name VARCHAR(255) := NULLIF(current_setting('app.user_name', true), '');
    v_correlation UUID       := NULLIF(current_setting('app.correlation_id', true), '')::UUID;
    v_row        roles%ROWTYPE;
BEGIN
    IF TG_OP = 'DELETE' THEN
        v_row := OLD;
    ELSE
        v_row := NEW;
    END IF;

    INSERT INTO roles_history (
        role_id, name, level, description, organization_id, is_system, created_at, updated_at,
        change_type, changed_by, changed_by_name, correlation_id
    ) VALUES (
        v_row.id, v_row.name, v_row.level, v_row.description, v_row.organization_id,
        v_row.is_system, v_row.created_at, v_row.updated_at,
        TG_OP, v_actor, v_actor_name, v_correlation
    );

    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_roles_history
    AFTER INSERT OR UPDATE OR DELETE ON roles
    FOR EACH ROW EXECUTE FUNCTION record_roles_history();

-- Grant history.
--
-- roles_history records that a role changed; it does not record which permissions it carries,
-- because those live in a different table. "Who gave this role the ability to manage access, and
-- when?" is the question an audit actually asks after an incident, and only this table answers it.
--
-- INSERT and DELETE only: a grant has no updatable column, so there is no UPDATE to record.
CREATE TABLE role_permissions_history (
    history_id      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    role_id         UUID        NOT NULL,
    permission_id   UUID        NOT NULL,
    organization_id UUID,
    change_type     VARCHAR(10) NOT NULL,
    changed_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    changed_by      UUID,
    changed_by_name VARCHAR(255),
    correlation_id  UUID
);

CREATE INDEX idx_role_permissions_history_role_id ON role_permissions_history (role_id);
CREATE INDEX idx_role_permissions_history_changed_at ON role_permissions_history (changed_at DESC);
CREATE INDEX idx_role_permissions_history_correlation_id ON role_permissions_history (correlation_id);

CREATE OR REPLACE FUNCTION record_role_permissions_history() RETURNS TRIGGER AS $$
DECLARE
    v_actor      UUID        := NULLIF(current_setting('app.user_id', true), '')::UUID;
    v_actor_name VARCHAR(255) := NULLIF(current_setting('app.user_name', true), '');
    v_correlation UUID       := NULLIF(current_setting('app.correlation_id', true), '')::UUID;
    v_role_id    UUID;
    v_permission_id UUID;
    v_org_id     UUID;
BEGIN
    IF TG_OP = 'DELETE' THEN
        v_role_id := OLD.role_id;
        v_permission_id := OLD.permission_id;
    ELSE
        v_role_id := NEW.role_id;
        v_permission_id := NEW.permission_id;
    END IF;

    -- Denormalised from the role so the history row carries its own tenant scope. Without it the
    -- RLS policy below would have to join a roles row that may since have been deleted, and the
    -- audit trail for a deleted role would become invisible to exactly the people investigating it.
    SELECT organization_id INTO v_org_id FROM roles WHERE id = v_role_id;

    INSERT INTO role_permissions_history (
        role_id, permission_id, organization_id, change_type, changed_by, changed_by_name,
        correlation_id
    ) VALUES (
        v_role_id, v_permission_id, v_org_id, TG_OP, v_actor, v_actor_name, v_correlation
    );

    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_role_permissions_history
    AFTER INSERT OR DELETE ON role_permissions
    FOR EACH ROW EXECUTE FUNCTION record_role_permissions_history();

-- ============================================================================
-- 4. Row-Level Security
--
-- roles and role_permissions were previously tenant-agnostic reference data with a permissive
-- policy. They now hold tenant-owned rows, so both need real predicates.
-- ============================================================================

-- Read: system roles (organization_id IS NULL) are visible to everyone — a firm has to be able
-- to see the platform roles it assigns.
-- Write: WITH CHECK omits the NULL branch, so a tenant can create and edit its OWN roles and can
-- never create, modify, or delete a system role. That asymmetry is the whole point.
DROP POLICY rls_default_allow ON roles;
CREATE POLICY rls_org_isolation ON roles
    USING (
        rls_is_bypass()
        OR organization_id IS NULL
        OR organization_id = ANY (rls_organization_ids())
    )
    WITH CHECK (rls_is_bypass() OR organization_id = ANY (rls_organization_ids()));

-- Grants follow their role's ownership. Without the WITH CHECK below, a firm administrator
-- could insert a row granting ACCESS_CONTROL:MANAGE to the VIEWER system role — editing a
-- platform role's meaning for every tenant on the platform.
DROP POLICY rls_default_allow ON role_permissions;
CREATE POLICY rls_org_isolation ON role_permissions
    USING (
        rls_is_bypass()
        OR EXISTS (
            SELECT 1 FROM roles r
            WHERE r.id = role_permissions.role_id
              AND (r.organization_id IS NULL OR r.organization_id = ANY (rls_organization_ids()))
        )
    )
    WITH CHECK (
        rls_is_bypass()
        OR EXISTS (
            SELECT 1 FROM roles r
            WHERE r.id = role_permissions.role_id
              AND r.organization_id = ANY (rls_organization_ids())
        )
    );

ALTER TABLE role_permissions_history ENABLE ROW LEVEL SECURITY;
ALTER TABLE role_permissions_history FORCE ROW LEVEL SECURITY;
CREATE POLICY rls_org_isolation ON role_permissions_history
    USING (
        rls_is_bypass()
        OR organization_id IS NULL
        OR organization_id = ANY (rls_organization_ids())
    );

ALTER TABLE roles_history ENABLE ROW LEVEL SECURITY;
ALTER TABLE roles_history FORCE ROW LEVEL SECURITY;
CREATE POLICY rls_org_isolation ON roles_history
    USING (
        rls_is_bypass()
        OR organization_id IS NULL
        OR organization_id = ANY (rls_organization_ids())
    );

-- The EXISTS predicates above run per row; without this the planner has no index to use for them.
CREATE INDEX idx_role_permissions_role_id ON role_permissions (role_id);

-- ============================================================================
-- 5. Permissions for the new surface
-- ============================================================================
INSERT INTO permissions (id, code, description) VALUES
    ('22222222-0000-4000-8000-00000000000c', 'USERS:INVITE',         'Invite a user and resend invitations'),
    ('22222222-0000-4000-8000-00000000000d', 'USERS:RESET_PASSWORD', 'Trigger a password reset for a user')
ON CONFLICT (code) DO NOTHING;

-- SUPER_ADMIN gets everything, including anything added later.
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r CROSS JOIN permissions p
WHERE r.name = 'SUPER_ADMIN' AND r.is_system
ON CONFLICT DO NOTHING;

-- A firm administrator manages their own people.
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r CROSS JOIN permissions p
WHERE r.name = 'ORG_ADMIN' AND r.is_system
  AND p.code IN ('USERS:INVITE', 'USERS:RESET_PASSWORD')
ON CONFLICT DO NOTHING;
