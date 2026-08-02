package com.jurivo.backend.module.rbac.model;

import com.jurivo.backend.shared.BaseEntity;
import lombok.Getter;
import lombok.Setter;
import org.springframework.data.relational.core.mapping.Table;

import java.time.Instant;

/**
 * A named, ranked bundle of permissions. Rows are reference data seeded by migration V3 — roles
 * are not created at runtime, because a role nobody granted permissions to is indistinguishable
 * from a typo.
 */
@Getter
@Setter
@Table("roles")
public class Role extends BaseEntity {

    private String name;

    /** Rank, used for "at least this senior" comparisons. Higher is more privileged. */
    private Integer level;

    private String description;
    private Instant createdAt;

    public Role() {
        super();
    }
}
