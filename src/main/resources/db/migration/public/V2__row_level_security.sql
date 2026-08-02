-- V2: Row-Level Security — the tenant isolation boundary.
--
-- Multi-tenant isolation in Jurivo is enforced by PostgreSQL, not by application code. A
-- missing WHERE clause in a repository method is a bug; a missing WHERE clause with RLS
-- underneath it is a bug that returns no extra rows. This is the difference between a
-- defect and an incident, and it is why RLS is non-negotiable for every new table.
--
-- HOW IT WORKS
--   1. On every connection checkout, RlsDataSource calls rls_prepare_session() with the
--      authenticated principal's organization ids, user id, name, and correlation id.
--   2. rls_prepare_session() sets session GUCs and switches to the non-superuser role
--      `jurivo_app` when filtering is required.
--   3. Every policy below reads those GUCs through the rls_*() helper functions.
--   4. On connection return, RlsDataSource calls rls_reset_session() so a pooled
--      connection can never carry one request's identity into the next.
--
-- BYPASS SEMANTICS
--   empty org id string  -> rls_organization_ids() IS NULL -> rls_is_bypass() TRUE
--                           (platform operator / unauthenticated bootstrap: all rows)
--   comma-separated uuid -> filtered to exactly those organizations
--   sentinel all-zero    -> a user belonging to no organization: matches nothing
--
-- Bypass is granted by the APPLICATION deciding not to pass org ids, which happens in
-- exactly two places: a SUPER_ADMIN principal, and the pre-authentication lookup that
-- resolves a Cognito sub to a user row. Nothing else may produce it.

-- ============================================================================
-- 1. The non-superuser application role
--
-- A PostgreSQL superuser bypasses every RLS policy unconditionally, and the local
-- development / Testcontainers user usually IS a superuser. Without this role switch, RLS
-- would appear to work in production and silently do nothing in tests — the exact failure
-- mode that makes an isolation bug survive to production.
-- ============================================================================
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'jurivo_app') THEN
        CREATE ROLE jurivo_app NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
    END IF;
END $$;

-- The connection user must be able to SET ROLE to it.
DO $$
BEGIN
    EXECUTE format('GRANT jurivo_app TO %I', current_user);
EXCEPTION
    WHEN duplicate_object THEN NULL;
END $$;

GRANT USAGE ON SCHEMA public TO jurivo_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO jurivo_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO jurivo_app;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO jurivo_app;

-- Future tables created by later migrations inherit these grants automatically. Without
-- this, every new migration would have to remember a GRANT block, and the one that forgot
-- would fail only in the environment whose connection user is not the table owner.
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO jurivo_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT USAGE, SELECT ON SEQUENCES TO jurivo_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT EXECUTE ON FUNCTIONS TO jurivo_app;

-- ============================================================================
-- 2. Helper functions
-- ============================================================================

-- The organization ids visible to the current session, or NULL for bypass.
-- STABLE (not IMMUTABLE) because it reads session state; the planner may still cache it
-- within a single statement, which is what makes per-row policy evaluation affordable.
CREATE OR REPLACE FUNCTION rls_organization_ids() RETURNS UUID[] AS $$
DECLARE
    raw_val TEXT;
BEGIN
    raw_val := NULLIF(current_setting('app.organization_ids', true), '');
    IF raw_val IS NULL THEN
        RETURN NULL;
    END IF;
    RETURN string_to_array(raw_val, ',')::UUID[];
EXCEPTION
    -- A malformed GUC must not fail open. Returning NULL here would grant bypass, so the
    -- only safe fallback is a value that matches nothing.
    WHEN OTHERS THEN
        RETURN ARRAY[]::UUID[];
END;
$$ LANGUAGE plpgsql STABLE;

CREATE OR REPLACE FUNCTION rls_is_bypass() RETURNS BOOLEAN AS $$
BEGIN
    RETURN rls_organization_ids() IS NULL;
END;
$$ LANGUAGE plpgsql STABLE;

CREATE OR REPLACE FUNCTION rls_user_id() RETURNS UUID AS $$
BEGIN
    RETURN NULLIF(current_setting('app.user_id', true), '')::UUID;
EXCEPTION
    WHEN OTHERS THEN
        RETURN NULL;
END;
$$ LANGUAGE plpgsql STABLE;

-- ============================================================================
-- 3. Session preparation / teardown
-- ============================================================================

CREATE OR REPLACE FUNCTION rls_prepare_session(
    p_org_ids        TEXT,
    p_user_id        TEXT,
    p_user_name      TEXT,
    p_correlation_id TEXT
) RETURNS void AS $$
BEGIN
    IF p_org_ids IS NOT NULL AND p_org_ids <> '' THEN
        -- Filtering required: drop to the non-superuser role so policies actually apply.
        EXECUTE 'RESET ROLE';
        EXECUTE 'SET ROLE jurivo_app';
    ELSIF current_setting('role') <> 'none' THEN
        -- Bypass required and a previous checkout left the role set: restore it.
        EXECUTE 'RESET ROLE';
    END IF;

    PERFORM set_config('app.organization_ids', COALESCE(p_org_ids, ''), false);
    PERFORM set_config('app.user_id', COALESCE(p_user_id, ''), false);
    PERFORM set_config('app.user_name', COALESCE(p_user_name, ''), false);
    PERFORM set_config('app.correlation_id', COALESCE(p_correlation_id, ''), false);
END;
$$ LANGUAGE plpgsql;

-- Called when a connection is returned to the pool. Clearing on return as well as setting
-- on checkout is belt and braces: a connection borrowed by anything that bypasses the
-- decorator (a migration, a health probe, a future direct-JDBC utility) starts clean
-- rather than inheriting whichever principal last used it.
CREATE OR REPLACE FUNCTION rls_reset_session() RETURNS void AS $$
BEGIN
    IF current_setting('role') <> 'none' THEN
        EXECUTE 'RESET ROLE';
    END IF;
    PERFORM set_config('app.organization_ids', '', false);
    PERFORM set_config('app.user_id', '', false);
    PERFORM set_config('app.user_name', '', false);
    PERFORM set_config('app.correlation_id', '', false);
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- 4. Policies
--
-- Every policy's FIRST condition is rls_is_bypass(). This is not stylistic: without it,
-- `organization_id = ANY(NULL::UUID[])` evaluates to NULL (not TRUE), so a platform
-- operator would be blocked from every row on every table.
--
-- FORCE ROW LEVEL SECURITY, not merely ENABLE: the table owner bypasses a plain ENABLE,
-- and in every deployed environment the connection user owns these tables.
-- ============================================================================

-- organizations: the tenant table itself keys on id, not organization_id.
ALTER TABLE organizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE organizations FORCE ROW LEVEL SECURITY;
CREATE POLICY rls_org_isolation ON organizations
    USING (rls_is_bypass() OR id = ANY (rls_organization_ids()))
    WITH CHECK (rls_is_bypass() OR id = ANY (rls_organization_ids()));

-- users: visible when the user's home organization is in scope, OR when they hold a
-- membership in an organization in scope. The EXISTS clause is what makes a firm able to
-- see its own staff whose home org is a sibling office. It does not recurse: the
-- user_organizations policy reads only its own column.
--
-- A user with a NULL organization_id and no membership rows (a platform operator) is
-- deliberately invisible to every tenant.
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE users FORCE ROW LEVEL SECURITY;
CREATE POLICY rls_org_isolation ON users
    USING (
        rls_is_bypass()
        OR organization_id = ANY (rls_organization_ids())
        OR EXISTS (
            SELECT 1 FROM user_organizations uo
            WHERE uo.user_id = users.id
              AND uo.organization_id = ANY (rls_organization_ids())
        )
    );

ALTER TABLE user_organizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_organizations FORCE ROW LEVEL SECURITY;
CREATE POLICY rls_org_isolation ON user_organizations
    USING (rls_is_bypass() OR organization_id = ANY (rls_organization_ids()))
    WITH CHECK (rls_is_bypass() OR organization_id = ANY (rls_organization_ids()));

-- user_roles: an org-scoped grant is visible to that org. A global grant (organization_id
-- NULL) is visible only when the grantee is themselves visible — otherwise every tenant
-- could enumerate the platform's operators by reading their global role rows.
ALTER TABLE user_roles ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_roles FORCE ROW LEVEL SECURITY;
CREATE POLICY rls_org_isolation ON user_roles
    USING (
        rls_is_bypass()
        OR organization_id = ANY (rls_organization_ids())
        OR EXISTS (
            SELECT 1 FROM user_organizations uo
            WHERE uo.user_id = user_roles.user_id
              AND uo.organization_id = ANY (rls_organization_ids())
        )
    );

-- History tables carry the same predicate as their base table. History that is readable
-- more widely than the row it describes is a leak with an audit trail attached.
ALTER TABLE organizations_history ENABLE ROW LEVEL SECURITY;
ALTER TABLE organizations_history FORCE ROW LEVEL SECURITY;
CREATE POLICY rls_org_isolation ON organizations_history
    USING (rls_is_bypass() OR organization_id = ANY (rls_organization_ids()));

ALTER TABLE users_history ENABLE ROW LEVEL SECURITY;
ALTER TABLE users_history FORCE ROW LEVEL SECURITY;
CREATE POLICY rls_org_isolation ON users_history
    USING (
        rls_is_bypass()
        OR organization_id = ANY (rls_organization_ids())
        OR EXISTS (
            SELECT 1 FROM user_organizations uo
            WHERE uo.user_id = users_history.user_id
              AND uo.organization_id = ANY (rls_organization_ids())
        )
    );

-- Tenant-agnostic reference data still gets an explicit permissive policy. A table with
-- RLS enabled and no policy denies everything; a table with neither is invisible to the
-- audit that checks "does every table have a policy". Being explicit makes the intent
-- reviewable.
ALTER TABLE roles ENABLE ROW LEVEL SECURITY;
ALTER TABLE roles FORCE ROW LEVEL SECURITY;
CREATE POLICY rls_default_allow ON roles USING (true);

ALTER TABLE permissions ENABLE ROW LEVEL SECURITY;
ALTER TABLE permissions FORCE ROW LEVEL SECURITY;
CREATE POLICY rls_default_allow ON permissions USING (true);

ALTER TABLE role_permissions ENABLE ROW LEVEL SECURITY;
ALTER TABLE role_permissions FORCE ROW LEVEL SECURITY;
CREATE POLICY rls_default_allow ON role_permissions USING (true);

ALTER TABLE cognito_group_role_mappings ENABLE ROW LEVEL SECURITY;
ALTER TABLE cognito_group_role_mappings FORCE ROW LEVEL SECURITY;
CREATE POLICY rls_default_allow ON cognito_group_role_mappings USING (true);
