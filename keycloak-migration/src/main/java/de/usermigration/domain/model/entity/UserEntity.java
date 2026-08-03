package de.usermigration.domain.model.entity;

import de.usermigration.domain.model.enums.RoleEnum;
import jakarta.persistence.*;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.*;
import org.hibernate.annotations.ColumnDefault;

import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Entity
@Table(name = "test_user", schema = "public", indexes = {
        @Index(name = "idx_user_1", columnList = "login", unique = true),
        @Index(name = "idx_user_keycloak_id", columnList = "keycloak_id")
})
public class UserEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id", nullable = false)
    private Long id;

    @Builder.Default
    @NotNull
    @ColumnDefault("true")
    @Column(name = "active", nullable = false)
    private boolean active = true;

    @Size(max = 255)
    @Column(name = "email")
    private String email;

    @Size(max = 255)
    @Column(name = "firstname")
    private String firstName;

    @Size(max = 255)
    @Column(name = "lastname")
    private String lastName;

    @Size(max = 255)
    @Column(name = "login")
    private String login;

    @Size(max = 255)
    @Column(name = "passwd")
    private String passwd;

    @Size(max = 255)
    @Column(name = "personalnr")
    private String personalNr;

    @Size(max = 255)
    @Column(name = "keycloak_id")
    private String keycloakId;

    @Column(name = "migrated_at")
    private LocalDateTime migratedAt;

    // ===================================================================
    // RoleGroups Relationship
    // ===================================================================

    /**
     * User → RoleGroup (Many-to-Many)
     * Join Table: TEST_USER_X_ROLE_GROUP
     */
    @Builder.Default
    @ManyToMany(fetch = FetchType.LAZY)
    @JoinTable(
            name = "test_user_x_role_group",
            joinColumns = @JoinColumn(name = "user_id"),
            inverseJoinColumns = @JoinColumn(name = "rolegroup_id")
    )
    private Set<RoleGroupEntity> roleGroups = new HashSet<>();

    // ===================================================================
    // Role Helper Methods (verwendet RoleEnum)
    // ===================================================================

    /**
     * Sammelt alle RoleEnums aus allen RoleGroups
     * Entspricht getRolesEnum() aus dem Original Code
     */
    public Set<RoleEnum> getRoleEnums() {
        return roleGroups.stream()
                .filter(rg -> !rg.isDeleted())  // Nur nicht-gelöschte RoleGroups
                .flatMap(rg -> rg.getRoles().stream())
                .filter(role -> !role.isDeleted())  // Nur nicht-gelöschte Roles
                .map(RoleEntity::getRoleEnumType)
                .filter(Objects::nonNull)
                .collect(Collectors.toSet());
    }

    /**
     * Rollen als String-Namen (für JWT & Keycloak)
     */
    public Set<String> getRoleNames() {
        return getRoleEnums().stream()
                .map(Enum::name)
                .collect(Collectors.toSet());
    }

    /**
     * Keycloak Rollennamen
     */
    public Set<String> getKeycloakRoleNames() {
        return getRoleEnums().stream()
                .map(RoleEnum::getKeycloakRoleName)
                .collect(Collectors.toSet());
    }

    /**
     * RoleGroup-Bezeichnungen für Logging/Debugging
     */
    public Set<String> getRoleGroupNames() {
        return roleGroups.stream()
                .filter(rg -> !rg.isDeleted())
                .map(RoleGroupEntity::getDesignation)
                .filter(Objects::nonNull)
                .collect(Collectors.toSet());
    }

    /**
     * Keycloak RoleGroup names (composite roles)
     */
    public Set<String> getKeycloakRoleGroupNames() {
        return roleGroups.stream()
                .filter(rg -> !rg.isDeleted())
                .map(RoleGroupEntity::getKeycloakRoleName)
                .filter(Objects::nonNull)
                .collect(Collectors.toSet());
    }

    /**
     * Get all RoleGroups (not deleted)
     */
    public Set<RoleGroupEntity> getActiveRoleGroups() {
        return roleGroups.stream()
                .filter(rg -> !rg.isDeleted())
                .collect(Collectors.toSet());
    }

    /**
     * Prüft ob User eine bestimmte Rolle hat (per String)
     */
    public boolean hasRole(String roleName) {
        return getRoleNames().contains(roleName);
    }

    /**
     * Prüft ob User eine bestimmte Rolle hat (per RoleEnum)
     */
    public boolean hasRole(RoleEnum roleEnum) {
        return getRoleEnums().contains(roleEnum);
    }

    /**
     * Fügt eine RoleGroup hinzu
     */
    public void addRoleGroup(RoleGroupEntity roleGroup) {
        this.roleGroups.add(roleGroup);
        roleGroup.getUsers().add(this);
    }

    /**
     * Entfernt eine RoleGroup
     */
    public void removeRoleGroup(RoleGroupEntity roleGroup) {
        this.roleGroups.remove(roleGroup);
        roleGroup.getUsers().remove(this);
    }

    /**
     * Prüft ob User System Admin ist
     */
    public boolean isSystemAdmin() {
        return hasRole(RoleEnum.SYSTEM_ADMIN);
    }

    /**
     * Prüft ob User Personnel-Rechte hat
     */
    public boolean hasPersonnelRights() {
        return getRoleEnums().stream().anyMatch(RoleEnum::isPersonnel);
    }

    /**
     * Prüft ob User Facility Workplan Rechte hat
     */
    public boolean hasFacilityWorkplanRights() {
        return getRoleEnums().stream().anyMatch(RoleEnum::isWorkplanManager);
    }

    /**
     * Gibt die höchste Hierarchie-Ebene zurück
     */
    public int getHighestHierarchyLevel() {
        return getRoleEnums().stream()
                .mapToInt(RoleEnum::getHierarchyLevel)
                .max()
                .orElse(0);
    }

    /**
     * Für Logging und Debugging
     */
    public String getRolesSummary() {
        return String.format("User %s has %d role groups (%s) with %d total roles: %s",
                login,
                roleGroups.size(),
                String.join(", ", getRoleGroupNames()),
                getRoleEnums().size(),
                getRoleNames());
    }
}
