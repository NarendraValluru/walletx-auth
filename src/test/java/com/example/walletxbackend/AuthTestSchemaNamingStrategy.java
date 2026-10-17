package com.example.walletxbackend;

import java.util.UUID;
import org.hibernate.boot.model.naming.Identifier;
import org.hibernate.boot.model.naming.PhysicalNamingStrategySnakeCaseImpl;
import org.hibernate.engine.jdbc.env.spi.JdbcEnvironment;

/** Redirects explicit auth mappings to an isolated schema in tests only. */
public class AuthTestSchemaNamingStrategy extends PhysicalNamingStrategySnakeCaseImpl {
    public static final String SCHEMA = "walletx_test_" + UUID.randomUUID().toString().replace("-", "");

    @Override
    public Identifier toPhysicalSchemaName(Identifier name, JdbcEnvironment environment) {
        if (name != null && "auth".equals(name.getText())) {
            return Identifier.toIdentifier(SCHEMA);
        }
        return super.toPhysicalSchemaName(name, environment);
    }
}

