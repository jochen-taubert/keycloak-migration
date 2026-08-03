package de.usermigration.infrastructure.persistence;

import de.usermigration.domain.model.entity.RoleEntity;
import de.usermigration.domain.model.entity.RoleGroupEntity;
import de.usermigration.domain.model.entity.UserEntity;
import de.usermigration.domain.model.enums.RoleEnum;
import de.usermigration.domain.model.enums.SystemOrigin;
import de.usermigration.infrastructure.persistence.repositories.RoleGroupRepository;
import de.usermigration.infrastructure.persistence.repositories.RoleRepository;
import de.usermigration.infrastructure.persistence.repositories.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Profile;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

/**
 * Seeds a handful of test users/roles/role-groups, but only on a genuinely fresh database
 * (no rows in test_user yet). On an existing database this is a no-op, so restarting the
 * app never duplicates or resets data.
 *
 * <p>Excluded from the {@code test} profile: KeycloakMigrationIntegrationTest (and any other
 * test activating that profile) manages its own test data with the same role-group
 * designations (e.g. "Admin Group"), and this seeder running alongside it would create a
 * second, seeder-owned "Admin Group" that the test's own cleanup logic doesn't know about.
 */
@Component
@Profile("!test")
@RequiredArgsConstructor
@Slf4j
public class TestDataSeeder implements CommandLineRunner {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final RoleGroupRepository roleGroupRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    @Transactional
    public void run(String... args) {
        if (userRepository.count() > 0) {
            log.info("Existing user data found, skipping test data seeding");
            return;
        }

        log.info("No existing user data found, seeding test data");

        RoleEntity systemAdminRole = roleRepository.save(
                RoleEntity.builder()
                        .roleEnumType(RoleEnum.SYSTEM_ADMIN)
                        .roleOrigin(SystemOrigin.TEST)
                        .build()
        );
        RoleEntity personnelRole = roleRepository.save(
                RoleEntity.builder()
                        .roleEnumType(RoleEnum.PERSONNEL)
                        .roleOrigin(SystemOrigin.TEST)
                        .build()
        );

        RoleGroupEntity adminGroup = RoleGroupEntity.builder()
                .designation("Admin Group")
                .description("Full system administration")
                .system(true)
                .userInternal(false)
                .build();
        adminGroup.addRole(systemAdminRole);
        roleGroupRepository.save(adminGroup);

        RoleGroupEntity personnelGroup = RoleGroupEntity.builder()
                .designation("Personnel Group")
                .description("Personnel management")
                .system(false)
                .userInternal(false)
                .build();
        personnelGroup.addRole(personnelRole);
        roleGroupRepository.save(personnelGroup);

        UserEntity admin = UserEntity.builder()
                .login("admin")
                .email("admin@example.com")
                .firstName("Admin")
                .lastName("User")
                .passwd(passwordEncoder.encode("admin123"))
                .personalNr("1000")
                .active(true)
                .build();
        admin.addRoleGroup(adminGroup);
        userRepository.save(admin);

        UserEntity personnel = UserEntity.builder()
                .login("personnel")
                .email("personnel@example.com")
                .firstName("Personnel")
                .lastName("User")
                .passwd(passwordEncoder.encode("personnel123"))
                .personalNr("1001")
                .active(true)
                .build();
        personnel.addRoleGroup(personnelGroup);
        userRepository.save(personnel);

        log.info("Test data seeded: 2 users, 2 roles, 2 role groups");
    }
}
