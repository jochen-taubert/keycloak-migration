package de.usermigration.infrastructure.rest;

import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Stand-in root config for @WebMvcTest slices in this package. The real
 * {@code UserMigrationApplication} carries @EnableJpaRepositories/@EntityScan directly on the
 * class, which @WebMvcTest can't exclude via excludeAutoConfiguration - it always tries (and
 * fails) to build an EntityManagerFactory. Spring's test bootstrapper picks the nearest
 * @SpringBootConfiguration to the test class's own package, so having this one here means
 * slice tests in this package use it instead of walking up to the real app class. Its default
 * component scan is limited to this package (and below), which is also exactly what keeps
 * @WebMvcTest's controller registration working.
 */
@SpringBootApplication
class WebSliceTestApplication {
}
