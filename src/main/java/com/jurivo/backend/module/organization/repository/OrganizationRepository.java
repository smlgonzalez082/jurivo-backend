package com.jurivo.backend.module.organization.repository;

import com.jurivo.backend.module.organization.model.Organization;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface OrganizationRepository extends CrudRepository<Organization, UUID> {

    Optional<Organization> findBySlug(String slug);

    boolean existsBySlug(String slug);

    /**
     * Every organization strictly inside the given nested-set bounds — i.e. the descendants of
     * the organization those bounds belong to, at any depth, in one index-backed query.
     */
    List<Organization> findByTreeRootIdAndTreeLeftGreaterThanAndTreeRightLessThan(
            UUID treeRootId, Integer treeLeft, Integer treeRight);

    List<Organization> findAllByOrderByNameAsc();
}
