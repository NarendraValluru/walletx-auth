package com.example.walletxbackend;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.beans.factory.annotation.Autowired;
import javax.sql.DataSource;
import static org.junit.jupiter.api.Assertions.*;
@EnabledIfSystemProperty(named="walletx.postgres.smoke", matches="true")
@SpringBootTest
class PostgresSmokeTest {
 @Autowired DataSource dataSource;
 @Test void configuredDatabaseAndAuthTablesAreAvailable() throws Exception {
  try(var c=dataSource.getConnection(); var statement=c.createStatement()) {
   assertEquals("PostgreSQL",c.getMetaData().getDatabaseProductName());
   try(var result=statement.executeQuery("select to_regclass('public.auth_users'), to_regclass('public.auth_sessions')")) {
    assertTrue(result.next()); assertNull(result.getString(1)); assertNull(result.getString(2));
   }
   try(var result=statement.executeQuery("select count(*) from auth.auth_users")) { assertTrue(result.next()); }
   try(var result=statement.executeQuery("select count(*) from auth.auth_sessions")) { assertTrue(result.next()); }
  }
 }
}
