package de.usermigration.infrastructure.keycloak;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * DTO für Migration Status/Statistiken
 * Zeigt den aktuellen Stand der Keycloak Migration
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class MigrationStatus {

    /**
     * Gesamtanzahl aktiver User
     */
    private long totalUsers;

    /**
     * Anzahl bereits migrierter User
     */
    private long migratedUsers;

    /**
     * Anzahl noch zu migrierender User
     */
    private long pendingUsers;

    /**
     * Migration Fortschritt in Prozent (0.0 - 100.0)
     */
    private double migrationPercentage;

    /**
     * Gibt zurück ob Migration abgeschlossen ist
     */
    public boolean isComplete() {
        return pendingUsers == 0 && totalUsers > 0;
    }

}
