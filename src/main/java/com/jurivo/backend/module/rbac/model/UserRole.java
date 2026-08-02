package com.jurivo.backend.module.rbac.model;

import com.jurivo.backend.shared.BaseEntity;
import lombok.Getter;
import lombok.Setter;
import org.springframework.data.relational.core.mapping.Table;

import java.time.Instant;
import java.util.UUID;

/**
 * A grant of one role to one user, optionally scoped to one organization.
 *
 * <p>A null {@code organizationId} is a platform-wide grant. Those are rare by design and should
 * stay that way: a global grant is not visible in any tenant's access-control screen, so it is
 * the kind of privilege that gets forgotten.
 */
@Getter
@Setter
@Table("user_roles")
public class UserRole extends BaseEntity {

    private UUID userId;
    private UUID roleId;
    private UUID organizationId;
    private Instant createdAt;

    public UserRole() {
        super();
    }
}
