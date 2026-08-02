package com.jurivo.backend.module.rbac.model;

import com.jurivo.backend.shared.BaseEntity;
import lombok.Getter;
import lombok.Setter;
import org.springframework.data.relational.core.mapping.Table;

import java.time.Instant;

/**
 * A single capability, coded {@code RESOURCE:ACTION} (for example {@code ORGANIZATIONS:READ}).
 *
 * <p>Codes are reference data seeded by migration V3 and referenced by string in
 * {@code @RequirePermission}. That string is the one link in the chain the compiler cannot
 * check, which is why the format is constrained in the schema and the codes are asserted
 * against the annotations in an integration test.
 */
@Getter
@Setter
@Table("permissions")
public class Permission extends BaseEntity {

    private String code;
    private String description;
    private Instant createdAt;

    public Permission() {
        super();
    }
}
