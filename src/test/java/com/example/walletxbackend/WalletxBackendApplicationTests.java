package com.example.walletxbackend;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import java.net.*;
import java.net.http.*;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;
@SpringBootTest(webEnvironment=SpringBootTest.WebEnvironment.RANDOM_PORT, properties={
 "spring.flyway.enabled=false",
 "spring.jpa.hibernate.ddl-auto=create-drop",
 "spring.jpa.properties.hibernate.hbm2ddl.create_namespaces=true",
 "walletx.auth.secret=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="})
class WalletxBackendApplicationTests {
 // Never create/drop tables in the application's auth schema.
 private static final String TEST_SCHEMA=AuthTestSchemaNamingStrategy.SCHEMA;
 @org.springframework.test.context.DynamicPropertySource
 static void isolatedPostgresSchema(org.springframework.test.context.DynamicPropertyRegistry registry) {
  registry.add("spring.jpa.hibernate.naming.physical-strategy", () -> AuthTestSchemaNamingStrategy.class.getName());
 }

 @org.springframework.beans.factory.annotation.Autowired org.springframework.security.oauth2.jwt.JwtEncoder encoder;
 @org.springframework.beans.factory.annotation.Autowired com.example.walletxbackend.repository.UserRepository users;
 @org.springframework.beans.factory.annotation.Autowired javax.sql.DataSource dataSource;
 @LocalServerPort int port;
 final HttpClient client=HttpClient.newHttpClient();
 HttpResponse<String> request(String method,String path,String body,String token) throws Exception {
  var b=HttpRequest.newBuilder(URI.create("http://localhost:"+port+path)).header("Content-Type","application/json");
  if(token!=null) b.header("Authorization","Bearer "+token);
  return client.send(b.method(method,body==null?HttpRequest.BodyPublishers.noBody():HttpRequest.BodyPublishers.ofString(body)).build(),HttpResponse.BodyHandlers.ofString());
 }
 String field(String json,String key) { var m=java.util.regex.Pattern.compile("\""+key+"\":\"([^\"]+)\"").matcher(json); assertTrue(m.find(),json); return m.group(1); }
 String credentials(String email,String password) { return "{\"email\":\""+email+"\",\"password\":\""+password+"\"}"; }
 @Test void lifecycleAndAuthorization() throws Exception {
  String c=credentials("User@example.com","correct-password-123");
  assertEquals(401,request("GET","/welcome",null,null).statusCode());
  assertEquals(201,request("POST","/api/v1/auth/register",c,null).statusCode());
  assertEquals(409,request("POST","/api/v1/auth/register",c,null).statusCode());
  assertEquals(401,request("POST","/api/v1/auth/login",credentials("User@example.com","wrong-password-123"),null).statusCode());
  var login=request("POST","/api/v1/auth/login",c,null); assertEquals(200,login.statusCode());
  assertEquals("no-store",login.headers().firstValue("Cache-Control").orElse(""));
  String access=field(login.body(),"accessToken"),refresh=field(login.body(),"refreshToken");
  assertEquals(200,request("GET","/api/v1/auth/me",null,access).statusCode());
  assertEquals(403,request("GET","/api/v1/admin/status",null,access).statusCode());
  String[] parts=access.split("\\.");
  String bad=parts[0]+"."+parts[1]+"."+(parts[2].startsWith("A")?"B":"A")+parts[2].substring(1);
  assertEquals(401,request("GET","/api/v1/auth/me",null,bad).statusCode());
  String body="{\"refreshToken\":\""+refresh+"\"}";
  var rotated=request("POST","/api/v1/auth/refresh",body,null); assertEquals(200,rotated.statusCode());
  assertEquals(401,request("POST","/api/v1/auth/refresh",body,null).statusCode());
  String nextAccess=field(rotated.body(),"accessToken"),nextRefresh=field(rotated.body(),"refreshToken");
  assertEquals(204,request("POST","/api/v1/auth/logout",null,nextAccess).statusCode());
  assertEquals(401,request("GET","/api/v1/auth/me",null,access).statusCode());
  assertEquals(401,request("GET","/api/v1/auth/me",null,nextAccess).statusCode());
  assertEquals(401,request("POST","/api/v1/auth/refresh","{\"refreshToken\":\""+nextRefresh+"\"}",null).statusCode());
 }
 @Test void validationAndLockout() throws Exception {
  assertEquals(400,request("POST","/api/v1/auth/register",credentials("bad","short"),null).statusCode());
  String c=credentials("locked@example.com","correct-password-123");
  assertEquals(201,request("POST","/api/v1/auth/register",c,null).statusCode());
  for(int i=0;i<5;i++) assertEquals(401,request("POST","/api/v1/auth/login",credentials("locked@example.com","incorrect-password"),null).statusCode());
  assertEquals(401,request("POST","/api/v1/auth/login",c,null).statusCode());
 }
 @Test void rejectsExpiredAndWrongAudienceAndAllowsAdmin() throws Exception {
  String email="admin@example.com", c=credentials(email,"correct-password-123");
  assertEquals(201,request("POST","/api/v1/auth/register",c,null).statusCode());
  var user=users.findByEmail(email).orElseThrow(); user.setRole("ADMIN"); users.saveAndFlush(user);
  var login=request("POST","/api/v1/auth/login",c,null);
  var access=field(login.body(),"accessToken");
  assertEquals(200,request("GET","/api/v1/admin/status",null,access).statusCode());
  var payload=new String(Base64.getUrlDecoder().decode(access.split("\\.")[1]),java.nio.charset.StandardCharsets.UTF_8);
  String sid=field(payload,"sid");
  for(boolean expired : List.of(true,false)) {
   var now=java.time.Instant.now();
   var claims=org.springframework.security.oauth2.jwt.JwtClaimsSet.builder().issuer("walletx-auth")
    .subject(user.getId().toString()).audience(List.of(expired?"walletx-api":"wrong-api"))
    .issuedAt(now.minusSeconds(600)).expiresAt(expired?now.minusSeconds(300):now.plusSeconds(600))
    .claim("sid",sid).claim("roles",List.of("ADMIN")).build();
   var token=encoder.encode(org.springframework.security.oauth2.jwt.JwtEncoderParameters.from(
    org.springframework.security.oauth2.jwt.JwsHeader.with(org.springframework.security.oauth2.jose.jws.MacAlgorithm.HS256).build(),claims)).getTokenValue();
   assertEquals(401,request("GET","/api/v1/auth/me",null,token).statusCode());
  }
 }

 @Test void schemaMigrationPreservesExistingRowsAndIsRepeatable() throws Exception {
  String suffix=UUID.randomUUID().toString().replace("-", "");
  String legacy="walletx_legacy_test_"+suffix, target="walletx_migration_test_"+suffix;
  try(var c=dataSource.getConnection(); var statement=c.createStatement()) {
   statement.execute("CREATE SCHEMA "+legacy);
   statement.execute("CREATE TABLE "+legacy+".auth_users (LIKE "+TEST_SCHEMA+".auth_users INCLUDING ALL)");
   statement.execute("CREATE TABLE "+legacy+".auth_sessions (LIKE "+TEST_SCHEMA+".auth_sessions INCLUDING ALL)");
   var userId=UUID.randomUUID(); var sessionId=UUID.randomUUID();
   statement.execute("INSERT INTO "+legacy+".auth_users (id,email,password_hash,role,failed_attempts) VALUES ('"+userId+"','migration@example.com','test-password-hash','USER',2)");
   statement.execute("INSERT INTO "+legacy+".auth_sessions (id,user_id,refresh_hash,expires_at,revoked) VALUES ('"+sessionId+"','"+userId+"','test-refresh-hash',CURRENT_TIMESTAMP+INTERVAL '1 day',false)");
   String beforeUser, beforeSession;
   try(var rows=statement.executeQuery("SELECT row_to_json(t)::text FROM "+legacy+".auth_users t")) { assertTrue(rows.next()); beforeUser=rows.getString(1); }
   try(var rows=statement.executeQuery("SELECT row_to_json(t)::text FROM "+legacy+".auth_sessions t")) { assertTrue(rows.next()); beforeSession=rows.getString(1); }
   var flyway=org.flywaydb.core.Flyway.configure().dataSource(dataSource).defaultSchema(target).schemas(target)
    .placeholders(Map.of("legacySchema",legacy)).locations("classpath:db/migration").load();
   assertEquals(1,flyway.migrate().migrationsExecuted);
   try(var rows=statement.executeQuery("SELECT row_to_json(t)::text FROM "+target+".auth_users t")) { assertTrue(rows.next()); assertEquals(beforeUser,rows.getString(1)); }
   try(var rows=statement.executeQuery("SELECT row_to_json(t)::text FROM "+target+".auth_sessions t")) { assertTrue(rows.next()); assertEquals(beforeSession,rows.getString(1)); }
   try(var rows=statement.executeQuery("SELECT to_regclass('"+legacy+".auth_users'), to_regclass('"+legacy+".auth_sessions')")) { assertTrue(rows.next()); assertNull(rows.getString(1)); assertNull(rows.getString(2)); }
   assertEquals(0,flyway.migrate().migrationsExecuted);
  } finally {
   // These names are generated above solely for this test; never clean auth/public.
   if(!legacy.matches("walletx_legacy_test_[0-9a-f]{32}") || !target.matches("walletx_migration_test_[0-9a-f]{32}")) throw new IllegalStateException("Unexpected test schema");
   try(var c=dataSource.getConnection(); var statement=c.createStatement()) {
    statement.execute("DROP SCHEMA IF EXISTS "+target+" CASCADE");
    statement.execute("DROP SCHEMA IF EXISTS "+legacy+" CASCADE");
   }
  }
 }

}
