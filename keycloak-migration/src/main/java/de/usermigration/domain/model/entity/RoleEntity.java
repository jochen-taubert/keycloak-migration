package de.usermigration.domain.model.entity;

import de.usermigration.domain.model.enums.RoleEnum;
import de.usermigration.domain.model.enums.SystemOrigin;
import jakarta.persistence.*;
import jakarta.validation.constraints.NotNull;
import lombok.*;
import org.hibernate.annotations.ColumnDefault;

import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.Set;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Entity
@Table(name = "test_role", schema = "public", indexes = {
        @Index(name = "uniq_role_1", columnList = "roletype")
})
public class RoleEntity {

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

    /**
     * RoleEnum Type - Das eigentliche Enum
     */
    @NotNull
    @Column(name = "roletype", nullable = false)
    @Enumerated(EnumType.STRING)
    private RoleEnum roleEnumType;

    @NotNull
    @Column(name = "roleorigin", nullable = false)
    @Enumerated(EnumType.STRING)
    private SystemOrigin roleOrigin;

    // ===================================================================
    // Relationships
    // ===================================================================

    /**
     * Role → RoleGroup (Many-to-Many, mapped by)
     */
    @Builder.Default
    @ManyToMany(mappedBy = "roles")
    private Set<RoleGroupEntity> roleGroups = new HashSet<>();

    // ===================================================================
    // Helper Methods
    // ===================================================================

    /**
     * Prüft ob diese Rolle gelöscht ist
     */
    public boolean isDeleted() {
        return this.deleted != 0;
    }

    /**
     * Gibt den Display-Namen der Rolle zurück
     */
    public String getDisplayName() {
        return roleEnumType != null ? roleEnumType.getDisplayName() : null;
    }

    /**
     * Gibt die Beschreibung der Rolle zurück
     */
    public String getDescription() {
        return roleEnumType != null ? roleEnumType.getDescription() : null;
    }

    /**
     * Gibt den Keycloak Rollennamen zurück
     */
    public String getKeycloakRoleName() {
        return roleEnumType != null ? roleEnumType.getKeycloakRoleName() : null;
    }
}
