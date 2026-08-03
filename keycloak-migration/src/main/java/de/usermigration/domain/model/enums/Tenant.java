package de.usermigration.domain.model.enums;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public enum Tenant {

    /** MPIBS */
    MPIBS("61", "Menüpartner"),

    /** KASS */
    KASS("62", "Apetito AG"),

    /** ACA */
    ACA("63", "Apetito Catering");

    private final String tenantNr;
    private final String tenantName;
}
