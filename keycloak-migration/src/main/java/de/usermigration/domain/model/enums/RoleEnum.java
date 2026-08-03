package de.usermigration.domain.model.enums;

import lombok.Getter;

import java.util.Arrays;

/**
 * Rollen-Enumeration für das Test-System
 * Enthält alle verfügbaren Rollen mit ihrer numerischen ID und Gruppenzuordnung
 */
@Getter
public enum RoleEnum {

    // Stammdaten
    FU_FACILITY_EDIT(1, 2006L, "Stammdaten: Einrichtungen"),
    FU_EDIT_FA_NR(28, 2028L, "Stammdaten: Einrichtungsnummer bearbeiten"),
    FU_FA_ASSIGN_COSTCENTER(28, 2044L, "Einrichtungsverwaltung: Kostenstelle/Projekt-Zuordnung"),
    FU_PERS_EDIT(2, 2000L, "Stammdaten: Personal"),
    FU_PERS_NR_EDIT(2, 2039L, "Stammdaten: Personal - Personalnummer bearbeiten"),
    FU_PERS_MEASLES_EDIT(2, 2045L, "Stammdaten: Personal - Nachweis Masernschutz bearbeiten"),
    FU_PERS_CRIMINAL_EDIT(2, 2046L, "Stammdaten: Personal - Führungszeugnis bearbeiten"),
    FU_PERS_CHANGES(2, 2050L, "Stammdaten: Personal - Stammdatenübertragung an LOGA"),
    FU_PERS_DELETE(2, 2051L, "Stammdaten: Personal löschen"),
    FU_DEPT_EDIT(3, 2008L, "Stammdaten: Betriebe"),
    FU_AG_EDIT(4, 2010L, "Stammdaten: Tätigkeitsgruppen"),
    FU_PARTNER_EDIT(5, 2012L, "Stammdaten: Partner"),

    // Kostenstellen
    FU_COST_CENTER_EDIT(6, 2011L, "Kostenstelle bearbeiten"),
    FU_COST_CENTER_VIEW(6, 2038L, "Kostenstelle nur lesen"),
    FU_COST_CENTER_ACTIVATION(6, 2041L, "Kostenstelle aktiv/inaktiv bearbeiten"),

    // Arbeitsverträge
    FU_PERS_CONTRACT_EDIT(7, 2001L, "Arbeitsverträge: Stammdaten bearbeiten"),
    FU_PERS_CONTRACT_PERS_NR(7, 2037L, "Arbeitsverträge: Personal-Nr. bearbeiten"),
    FU_PERS_CONTRACT_VIEW(7, 2035L, "Arbeitsverträge: Nur Vorschau"),
    FU_PERS_CONTRACT_DELETE(7, 2052L, "Arbeitsverträge: Arbeitsvertrag löschen"),
    FU_PERS_TAKEOVER(7, 2031L, "Arbeitsverträge: Personalstammdaten übernehmen"),
    FU_PERS_CONTRACT_PRINT(7, 2036L, "Arbeitsverträge: MS Word Vorlagen drucken"),
    FU_DOCX_TEMPLATES(7, 2025L, "Arbeitsverträge: MS Word Vorlagen bearbeiten"),
    FU_PERS_CONTRACT_SYNCH(7, 2057L, "Arbeitsverträge: Personalstammdaten synchronisieren"),

    // Arbeitspläne
    FU_PERS_WORKPLAN(8, 2002L, "Arbeitsplan: nach Mitarbeiter"),
    FU_FACILITY_WORKPLAN(9, 2007L, "Arbeitsplan: nach Einrichtung"),
    FU_DEPT_WORKPLAN(10, 2009L, "Arbeitsplan: nach Betrieb"),
    FU_PERS_WORKPLAN_REVIEW(11, 2003L, "Arbeitsplan: Wochen-Auswertung"),
    FU_PERS_WORKTIME(12, 2004L, "Arbeitsplan: Zeitabgleich"),
    FU_EDIT_DOWNTIME_ALL(12, 2042L, "Ausfallcodes: Alle MP"),
    FU_EDIT_DOWNTIME_DEPTMANAGER(12, 2043L, "Ausfallcodes: Betriebsleiter"),

    // LOGA & Monatsabschluss
    FU_LOGA_TRANSFER(13, 2019L, "LOGA-Transfer"),
    FU_MONTH_CLOSE(14, 2018L, "Monatsabschluss"),
    FU_MONTH_CLOSE_F_C(14, 2034L, "Monatsabschluss (Endg. und Korrekt.)"),

    // Berichte
    FU_REP_PERS_LIST(15, 2005L, "Bericht: Personallisten"),
    FU_REP_IS_HOURS(16, 2013L, "Bericht: Kostenstellen"),
    FU_REP_ABSENCES(17, 2014L, "Bericht: Krankmeldungen (AK)"),

    // Zeitstempel
    FU_TRM_MANAGEMENT(18, 2015L, "Zeitstempel-Verwaltung"),
    FU_TRM_INSERT(18, 2033L, "System: Zeitstempel-Erstellung"),

    // Dashboard
    FU_DASH_NEW_CONTRACTS(20, 2020L, "Dashboard: neue Arbeitsverträge"),
    FU_DASH_EXP_TRIAL_CONTRACTS(21, 2021L, "Dashboard: Demnächst ablaufende Probezeit"),
    FU_DASH_HISTORY(22, 2022L, "Dashboard: Systemlog"),
    FU_DASH_MONTH_CLOSE(23, 2023L, "Dashboard: Monatsabschluss"),
    FU_DASH_EXP_EMPLOYMENT(23, 2040L, "Dashboard: Demnächst ablaufende Beschäftigung"),
    FU_DASH_INCOMING_BIRTHDAYS(2, 2068L, "Dashboard: Geburtstage"),

    // System
    FU_MASTERDATA_IMPORT(24, 2016L, "System: Stammdaten-Import (SKITBS)"),
    FU_MASTERDATA_MIGRATION(25, 2017L, "System: Stammdaten-Migration"),
    FU_USERS_MANAGEMENT(26, 2024L, "System: Benutzerverwaltung"),
    FU_PERS_TRANSFER(32, 2032L, "System: Personal-Transfer (REST)"),

    // Stammdaten Download
    FU_MD_DOWNLOAD_VIEW(18, 2047L, "Stammdaten Download: Vorschau"),
    FU_MD_DOWNLOAD_PERS(18, 2048L, "Stammdaten Download: Mitarbeiter"),
    FU_MD_DOWNLOAD_FA(18, 2049L, "Stammdaten Download: Einrichtung"),

    // SuC Akademie
    FU_COURSE_MANAGEMENT(19, 2053L, "SuC Akademie - Verwaltung"),
    FU_COURSE_ATTENDENCES(19, 2054L, "SuC Akademie - Kursabsolvierung"),

    // Verträge
    FU_VMTR_VIEW(20, 2055L, "Verträge: Bearbeitung"),
    FU_VMTR_EDIT(21, 2056L, "Verträge: Vorschau"),

    // AZK
    FU_AZK_REVIEW(11, 2058L, "AZK-Auswertung"),
    FU_AZK_EDIT(2, 2069L, "AZK-Auswertung bearbeiten"),

    // Personal Zusatzfunktionen
    FU_PERS_RETURNEE_TO_LOGA(2, 2059L, "Stammdaten: Personal - Neuen Vertrag in Loga anlegen"),
    FU_PERS_EPOST(2, 2060L, "E-Post Zugangsdaten drucken"),
    FU_PERS_EPOST_CTRL(2, 2061L, "E-Post Versandt auslösen"),
    FU_PERS_FA_MIN_WAGE(2, 2062L, "Auswertung Einrichtung-Mindestlohn"),
    FU_PERS_MONTH_ACC_CONFIG(2, 2063L, "Personalstammdaten: Abrechnungs-Konfiguration bearbeiten"),
    FU_LOGA_TRANSFER_MGMT(2, 2064L, "LOGA-Transfer: Daten nach Loga senden"),
    FU_PAYMENT_RATE_VIEW(2, 2065L, "Stammdaten: Personal - Lohnbeträge anzeigen"),
    FU_PKU_TRANSFER(2, 2066L, "PKU Transfer"),
    FU_FA_CREATE(2, 2067L, "Stammdaten: Einrichtungen - Einrichtung erstellen"),
    FU_EDIT_MEAL_WORKING_HOURS(2, 2071L, "Arbeitszeiten/Verpflegung"),

    // Spezielle Gruppenrollen
    SYSTEM_ADMIN(28, 1002L, "(Sys.) Administrator"),
    MOBILE_ADMIN(29, 1003L, "(Sys.) Administrator-Mobile"),
    PERSONNEL(32, 1006L, "(Sys.) Personal"),
    QM_OPERATOR(34, 1008L, "(Sys.) QM Betreiber"),
    QM_MANAGER(34, 1009L, "(Sys.) QM Manager"),
    WEB_USER(9999, 1001L, "Web");

    // ===================================================================
    // Enum Properties (mit Lombok @Getter)
    // ===================================================================

    private final int groupId;
    private final long roleId;
    private final String description;

    RoleEnum(int groupId, long roleId, String description) {
        this.groupId = groupId;
        this.roleId = roleId;
        this.description = description;
    }

    // ===================================================================
    // Helper Methods
    // ===================================================================

    /**
     * Gibt die numerische Rollen-ID als String zurück (für Legacy-Kompatibilität)
     */
    public String getRoleIdString() {
        return String.valueOf(roleId);
    }

    /**
     * Gibt den Anzeigenamen zurück (Alias für description, für Rückwärtskompatibilität)
     */
    public String getDisplayName() {
        return description;
    }

    /**
     * Gibt das Hierarchie-Level zurück (höher = mehr Rechte)
     * System-Rollen (1xxx) haben höchste Priorität
     */
    public int getHierarchyLevel() {
        return switch (this) {
            case SYSTEM_ADMIN -> 100;
            case MOBILE_ADMIN -> 90;
            case QM_MANAGER -> 80;
            case QM_OPERATOR -> 70;
            case PERSONNEL -> 60;
            case WEB_USER -> 10;
            default -> groupId; // FU_* Rollen verwenden groupId als Hierarchie
        };
    }

    /**
     * Prüft ob diese Rolle Admin-Rechte hat
     */
    public boolean isAdmin() {
        return this == SYSTEM_ADMIN;
    }

    /**
     * Prüft ob diese Rolle Personnel-Rechte hat
     */
    public boolean isPersonnel() {
        return this == PERSONNEL || this == SYSTEM_ADMIN;
    }

    /**
     * Prüft ob diese Rolle Workplan-Rechte hat
     */
    public boolean isWorkplanManager() {
        return this == FU_FACILITY_WORKPLAN || this == SYSTEM_ADMIN;
    }

    /**
     * Gibt den Keycloak Rollennamen zurück
     */
    public String getKeycloakRoleName() {
        return this.name();
    }

    /**
     * Findet RoleEnum per numerischer ID
     */
    public static RoleEnum fromRoleId(long roleId) {
        return Arrays.stream(RoleEnum.values())
                .filter(role -> role.roleId == roleId)
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException("Unknown role ID: %d".formatted(roleId)));
    }

    /**
     * Findet RoleEnum per Name (case-insensitive)
     * Entfernt automatisch gängige Prefixe (backwards compatibility)
     *
     * @param name Role Name (z.B. "SYSTEM_ADMIN", "PERSONNEL", "FU_FACILITY_WORKPLAN")
     * @return RoleEnum
     * @throws IllegalArgumentException wenn Role nicht gefunden
     */
    public static RoleEnum fromString(String name) {
        if (name == null || name.isBlank()) {
            throw new IllegalArgumentException("Role name cannot be null or blank");
        }

        // Entferne mögliche Prefixe (backwards compatibility)
        String cleanName = name
                .replace("ROLE_", "")
                .trim();

        return Arrays.stream(RoleEnum.values())
                .filter(role -> role.name().equalsIgnoreCase(cleanName))
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException("Unknown role: %s".formatted(name)));
    }

    @Override
    public String toString() {
        return description;
    }
}
