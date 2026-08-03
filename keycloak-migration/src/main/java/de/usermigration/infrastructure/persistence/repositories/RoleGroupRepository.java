package de.usermigration.infrastructure.persistence.repositories;

import de.usermigration.domain.model.entity.RoleGroupEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface RoleGroupRepository extends JpaRepository<RoleGroupEntity, Long> {

    Optional<RoleGroupEntity> findByDesignation(String designation);
}
