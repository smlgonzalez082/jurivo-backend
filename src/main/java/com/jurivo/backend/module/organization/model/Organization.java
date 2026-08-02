package com.jurivo.backend.module.organization.model;

import com.jurivo.backend.shared.BaseEntity;
import lombok.Getter;
import lombok.Setter;
import org.springframework.data.relational.core.mapping.Table;

import java.time.Instant;
import java.util.UUID;

/**
 * The tenant. Every piece of client data in Jurivo hangs off exactly one of these.
 *
 * <p>Organizations form a nested-set forest: a standalone firm is a tree of one, and a firm with
 * offices or acquired practices is a tree whose root can be granted visibility over the whole
 * subtree with a single range predicate. {@code treeRootId}/{@code treeLeft}/{@code treeRight}
 * are maintained by {@code OrganizationService} and must not be written anywhere else — an
 * inconsistent nested set does not throw, it silently changes who can see what.
 */
@Getter
@Setter
@Table("organizations")
public class Organization extends BaseEntity {

    private String name;
    private String slug;

    /**
     * Lifecycle state. Engineering Principle 13: {@code OrganizationService#changeStatus} is the
     * only writer of this field. Nothing else assigns it, including on creation.
     */
    private String status;

    private UUID parentId;
    private UUID treeRootId;
    private Integer treeLeft;
    private Integer treeRight;
    private Instant createdAt;
    private Instant updatedAt;

    public Organization() {
        super();
    }
}
