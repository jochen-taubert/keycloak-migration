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
@Table(name = "test_role_group", schema = "public", indexes = {
        @Index(name = "uniq_rolegroup_1", columnList = "designation", unique = true)
})
public class RoleGroupEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id", nullable = false)
    private Long id;

    @Column(name = "created")
    private LocalDateTime created;

    @Builder.Default
    @NotNull
    @ColumnDefault("0")
    @Column(name = "deleted", nullable = false)
    private Integer deleted = 0;

    @Column(name = "modified")
    private LocalDateTime modified;

    @Version
    @Column(name = "version")
    private Long version;

    @NotNull
    @Column(name = "system", nullable = false)
    private Boolean system;

    @NotNull
    @Column(name = "userinternal", nullable = false)
    private Boolean userInternal;

    @Size(max = 255)
    @NotNull
    @Column(name = "designation", nullable = false)
    private String designation;

    @Size(max = 500)
    @Column(name = "description", length = 500)
    private String description;

    // ===================================================================
    // Relationships
    // ===================================================================

    /**
     * RoleGroup → Role (Many-to-Many)
     * Join Table: TEST_ROLE_GROUP_X_ROLE
     */
    @Builder.Default
    @ManyToMany(fetch = FetchType.LAZY)
    @JoinTable(
            name = "test_role_group_x_role",
            joinColumns = @JoinColumn(name = "rolegroup_id"),
            inverseJoinColumns = @JoinColumn(name = "role_id")
    )
    private Set<RoleEntity> roles = new HashSet<>();

    /**
     * RoleGroup → User (Many-to-Many, mapped by)
     */
    @Builder.Default
    @ManyToMany(mappedBy = "roleGroups")
    private Set<UserEntity> users = new HashSet<>();

    // ===================================================================
    // Helper Methods
    // ===================================================================

    /**
     * Fügt eine Rolle zur RoleGroup hinzu
     */
    public void addRole(RoleEntity role) {
        this.roles.add(role);
        role.getRoleGroups().add(this);
    }

    /**
     * Entfernt eine Rolle von der RoleGroup
     */
    public void removeRole(RoleEntity role) {
        this.roles.remove(role);
        role.getRoleGroups().remove(this);
    }

    /**
     * Prüft ob diese RoleGroup gelöscht ist
     */
    public boolean isDeleted() {
        return this.deleted != 0;
    }

    /**
     * Prüft ob diese RoleGroup eine System-RoleGroup ist
     */
    public boolean isSystemRoleGroup() {
        return Boolean.TRUE.equals(this.system);
    }

    /**
     * Prüft ob diese RoleGroup für interne User ist
     */
    public boolean isInternalRoleGroup() {
        return Boolean.TRUE.equals(this.userInternal);
    }

    /**
     * Gibt alle RoleEnums dieser RoleGroup zurück
     */
    public Set<RoleEnum> getRoleEnums() {
        return roles.stream()
                .filter(role -> !role.isDeleted())
                .map(RoleEntity::getRoleEnumType)
                .filter(Objects::nonNull)
                .collect(Collectors.toSet());
    }

    /**
     * Keycloak composite role name for this RoleGroup
     * Format: RG_{DESIGNATION_UPPERCASE_WITH_UNDERSCORES}
     */
    public String getKeycloakRoleName() {
        if (designation == null) return null;
        return "RG_" + designation.toUpperCase()
                .replaceAll("[^A-Z0-9]", "_")
                .replaceAll("_+", "_");
    }

    /**
     * Keycloak role names for all roles in this RoleGroup
     */
    public Set<String> getKeycloakRoleNames() {
        return getRoleEnums().stream()
                .map(RoleEnum::getKeycloakRoleName)
                .collect(Collectors.toSet());
    }
}
