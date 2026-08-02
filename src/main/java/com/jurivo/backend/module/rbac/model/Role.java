package com.jurivo.backend.module.rbac.model;

import com.jurivo.backend.shared.BaseEntity;
import lombok.Getter;
import lombok.Setter;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.time.Instant;
import java.util.UUID;

/**
 * A named bundle of permissions.
 *
 * <p>Two kinds, distinguished by {@link #isSystem}:
 *
 * <ul>
 *   <li><b>System roles</b> ({@code organizationId} null, {@code isSystem} true) are
 *       platform-owned and immutable — SUPER_ADMIN, ORG_ADMIN, MEMBER, VIEWER. Only these
 *       satisfy a {@code @RequireRole} check or grant tenant-isolation bypass.
 *   <li><b>Custom roles</b> are owned by one organization and created by its administrators.
 *       They contribute permissions and nothing else.
 * </ul>
 *
 * <p><b>Names are unique per organization, not globally.</b> Two firms can each have a
 * "Paralegal". Anything that resolves permissions must key on the role ID; resolving by name
 * would union unrelated firms' grants.
 */
@Getter
@Setter
@Table("roles")
public class Role extends BaseEntity {

    private String name;

    /** Rank, for "at least this senior" comparisons. Custom roles sit below every system role. */
    private Integer level;

    private String description;

    /** Owning organization. Null for a platform role. */
    private UUID organizationId;

    /**
     * Column mapped explicitly.
     *
     * <p>Lombok generates {@code isSystem()} for a {@code boolean isSystem} field, and the
     * JavaBeans property name derived from that getter is {@code system} — which snake-cases to a
     * column named {@code system} rather than {@code is_system}. Whether that bites depends on
     * whether the mapper resolves by field or by accessor, which is not a thing to leave to
     * inference on the field that decides whether a role is platform-owned.
     */
    @Column("is_system")
    private boolean isSystem;

    private Instant createdAt;
    private Instant updatedAt;

    public Role() {
        super();
    }
}
