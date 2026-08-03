package de.usermigration.infrastructure.persistence.repositories;

import de.usermigration.domain.model.entity.RoleEntity;
import de.usermigration.domain.model.enums.RoleEnum;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface RoleRepository extends JpaRepository<RoleEntity, Long> {

    Optional<RoleEntity> findByRoleEnumType(RoleEnum roleEnumType);
}
