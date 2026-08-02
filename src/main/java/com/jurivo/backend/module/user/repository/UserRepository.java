package com.jurivo.backend.module.user.repository;

import com.jurivo.backend.module.user.model.User;
import org.springframework.data.jdbc.repository.query.Query;
import org.springframework.data.repository.CrudRepository;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface UserRepository extends CrudRepository<User, UUID> {

    Optional<User> findByIdpSub(String idpSub);

    /**
     * Case-insensitive email lookup, matching the {@code idx_users_email_lower} unique index.
     * Written as SQL rather than a derived {@code IgnoreCase} query so the predicate is
     * guaranteed to be the exact expression the index was built on — a derived query that
     * lowercases only one side would silently fall back to a sequential scan.
     */
    @Query("SELECT * FROM users WHERE LOWER(email) = LOWER(:email)")
    Optional<User> findByEmailIgnoringCase(@Param("email") String email);

    List<User> findByOrganizationId(UUID organizationId);

    /**
     * Every user the session can see, ordered for display.
     *
     * <p>No tenant predicate: Row-Level Security supplies it. Ordering lives here rather than in
     * the service so the database sorts, and so a caller cannot forget to.
     */
    @Query("SELECT * FROM users ORDER BY COALESCE(full_name, email), email")
    List<User> findAllOrdered();
}
