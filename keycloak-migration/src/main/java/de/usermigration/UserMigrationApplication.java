package de.usermigration;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;

@SpringBootApplication
@EntityScan(basePackages = "de.usermigration.domain.model.entity")
@EnableJpaRepositories(basePackages = "de.usermigration.infrastructure.persistence.repositories")
public class UserMigrationApplication {

    public static void main(String[] args) {
        SpringApplication.run(UserMigrationApplication.class, args);
    }

}
