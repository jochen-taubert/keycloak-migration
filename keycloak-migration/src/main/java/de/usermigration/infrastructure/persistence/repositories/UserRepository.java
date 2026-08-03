package de.usermigration.infrastructure.persistence.repositories;

import de.usermigration.domain.model.entity.UserEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<UserEntity, Long> {

    // ===================================================================
    // Basis-Queries (ohne Eager Loading)
    // ===================================================================

    Optional<UserEntity> findByLogin(String login);

    Optional<UserEntity> findByKeycloakId(String keycloakId);

    List<UserEntity> findByKeycloakIdIsNull();

    boolean existsByLogin(String login);

    boolean existsByKeycloakId(String keycloakId);

    Optional<UserEntity> findByEmail(String email);

    boolean existsByEmail(String email);

    // ===================================================================
    // Authentication & Migration Queries (MIT Eager Loading)
    // ===================================================================

    /**
     * ✅ WICHTIG: Für Authentication verwenden!
     * Lädt User MIT RoleGroups UND Roles in EINER Query
     */
    @Query("SELECT DISTINCT u FROM UserEntity u " +
            "LEFT JOIN FETCH u.roleGroups rg " +
            "LEFT JOIN FETCH rg.roles r " +
            "WHERE u.login = :login")
    Optional<UserEntity> findByLoginWithRoles(@Param("login") String login);
}
