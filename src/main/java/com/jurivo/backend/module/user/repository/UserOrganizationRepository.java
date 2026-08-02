package com.jurivo.backend.module.user.repository;

import com.jurivo.backend.module.user.model.UserOrganization;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.UUID;

@Repository
public interface UserOrganizationRepository extends CrudRepository<UserOrganization, UUID> {

    List<UserOrganization> findByUserId(UUID userId);

    List<UserOrganization> findByOrganizationId(UUID organizationId);
}
