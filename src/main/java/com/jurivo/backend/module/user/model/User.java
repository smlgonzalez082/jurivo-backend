package com.jurivo.backend.module.user.model;

import com.jurivo.backend.shared.BaseEntity;
import lombok.Getter;
import lombok.Setter;
import org.springframework.data.relational.core.mapping.Table;

import java.time.Instant;
import java.util.UUID;

/**
 * A person who can sign in.
 *
 * <p>{@code idpSub} — the Amazon Cognito {@code sub} — is the identity key and the only field
 * used to match an incoming token to a row. Email is display and search data: Cognito permits an
 * address to be changed or reassigned, and matching on it would eventually attach one person's
 * audit history to another.
 */
@Getter
@Setter
@Table("users")
public class User extends BaseEntity {

    private String idpSub;
    private String email;
    private String fullName;

    /** Home organization. Null for a platform operator, who belongs to no tenant. */
    private UUID organizationId;

    private String status;
    private Instant lastLoginAt;
    private Instant createdAt;
    private Instant updatedAt;

    public User() {
        super();
    }
}
