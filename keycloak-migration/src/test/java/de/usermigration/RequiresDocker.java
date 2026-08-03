package de.usermigration;

import org.testcontainers.junit.jupiter.EnabledIfDockerAvailable;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Target({ ElementType.TYPE, ElementType.METHOD })
@Retention(RetentionPolicy.RUNTIME)
@EnabledIfDockerAvailable
public @interface RequiresDocker {
}
