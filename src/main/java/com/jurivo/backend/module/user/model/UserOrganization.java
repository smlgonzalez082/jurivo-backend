package com.jurivo.backend.module.user.model;

import com.jurivo.backend.shared.BaseEntity;
import lombok.Getter;
import lombok.Setter;
import org.springframework.data.relational.core.mapping.Table;

import java.time.Instant;
import java.util.UUID;

/** A user's membership in one organization. */
@Getter
@Setter
@Table("user_organizations")
public class UserOrganization extends BaseEntity {

    private UUID userId;
    private UUID organizationId;
    private Instant createdAt;

    public UserOrganization() {
        super();
    }
}
