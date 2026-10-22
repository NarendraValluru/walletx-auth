package com.example.walletxbackend;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import java.net.*;
import java.net.http.*;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;
@SpringBootTest(webEnvironment=SpringBootTest.WebEnvironment.RANDOM_PORT, properties={
 "walletx.introspection.client-secret=integration-test-service-secret-at-least-32-characters",
 "spring.flyway.enabled=false",
 "spring.jpa.hibernate.ddl-auto=create-drop",
 "spring.jpa.properties.hibernate.hbm2ddl.create_namespaces=true",
 "walletx.auth.secret=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="})
class WalletxBackendApplicationTests {
 // Never create/drop tables in the application's auth schema.
 private static final String TEST_SCHEMA=AuthTestSchemaNamingStrategy.SCHEMA;
 private static final java.nio.file.Path RESET_OUTBOX=java.nio.file.Path.of("target","reset-mail-test-"+UUID.randomUUID());
 @org.springframework.test.context.DynamicPropertySource
 static void isolatedPostgresSchema(org.springframework.test.context.DynamicPropertyRegistry registry) {
  registry.add("spring.jpa.hibernate.naming.physical-strategy", () -> AuthTestSchemaNamingStrategy.class.getName());
  registry.add("walletx.auth.reset.outbox", () -> RESET_OUTBOX.toString());
  registry.add("walletx.auth.reset.delivery", () -> "file");
  registry.add("walletx.auth.reset.url", () -> "http://localhost:5173/reset-password");
 }

 @org.springframework.beans.factory.annotation.Autowired org.springframework.security.oauth2.jwt.JwtEncoder encoder;
 @org.springframework.beans.factory.annotation.Autowired org.springframework.security.oauth2.jwt.JwtDecoder decoder;
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
 String registration(String credentials) { return "{\"fullName\":\"Test WalletX User\","+credentials.substring(1); }
 HttpResponse<String> browserPost(HttpClient browser,String path,String body) throws Exception {
  String base="http://localhost:"+port;
  var csrf=browser.send(HttpRequest.newBuilder(URI.create(base+"/api/v1/auth/browser/csrf")).GET().build(),HttpResponse.BodyHandlers.ofString());
  return browser.send(HttpRequest.newBuilder(URI.create(base+"/api/v1/auth/browser/"+path))
    .header("Content-Type","application/json").header("X-XSRF-TOKEN",field(csrf.body(),"token"))
    .POST(HttpRequest.BodyPublishers.ofString(body)).build(),HttpResponse.BodyHandlers.ofString());
 }
 String deliveredToken(String email) throws Exception {
  try(var paths=java.nio.file.Files.list(RESET_OUTBOX)) {
   for(var path:paths.toList()) {
    String mail=java.nio.file.Files.readString(path);
    if(mail.startsWith("To: "+email+"\n")) {
     var match=java.util.regex.Pattern.compile("#token=([A-Za-z0-9_-]{43})").matcher(mail);
     assertTrue(match.find()); return match.group(1);
    }
   }
  }
  throw new AssertionError("No reset email delivered");
 }
 @Test void fullNameIsRequiredAndReturnedInProfile() throws Exception {
  String c=credentials("name-"+UUID.randomUUID()+"@example.com","correct-password-123");
  assertEquals(400,request("POST","/api/v1/auth/register",c,null).statusCode());
  assertEquals(400,request("POST","/api/v1/auth/register","{\"fullName\":\"   \","+c.substring(1),null).statusCode());
  var created=request("POST","/api/v1/auth/register",registration(c),null);
  assertEquals(201,created.statusCode()); assertEquals("Test WalletX User",field(created.body(),"fullName"));
  var login=request("POST","/api/v1/auth/login",c,null);
  assertEquals("Test WalletX User",field(request("GET","/api/v1/auth/me",null,field(login.body(),"accessToken")).body(),"fullName"));
 }
 @Test void passwordResetIsPrivateSingleUseExpiringAndRevokesAllSessions() throws Exception {
  String email="reset-"+UUID.randomUUID()+"@example.com", original="correct-password-123", replacement="replacement-password-456";
  String c=credentials(email,original);
  assertEquals(201,request("POST","/api/v1/auth/register",registration(c),null).statusCode());
  var first=request("POST","/api/v1/auth/login",c,null);
  var second=request("POST","/api/v1/auth/login",c,null);
  var browser=HttpClient.newBuilder().cookieHandler(new CookieManager(null,CookiePolicy.ACCEPT_ALL)).build();
  assertEquals(403,request("POST","/api/v1/auth/browser/forgot-password","{\"email\":\""+email+"\"}",null).statusCode());
  var known=browserPost(browser,"forgot-password","{\"email\":\""+email+"\"}");
  var unknown=browserPost(browser,"forgot-password","{\"email\":\"unknown-"+UUID.randomUUID()+"@example.com\"}");
  assertEquals(202,known.statusCode()); assertEquals(known.body(),unknown.body());
  assertFalse(known.body().contains("token"));
  String token=deliveredToken(email);
  var user=users.findByEmail(email).orElseThrow();
  assertNotEquals(token,user.getResetTokenHash()); assertEquals(64,user.getResetTokenHash().length());
  assertTrue(user.getResetExpiresAt().isAfter(java.time.Instant.now().plusSeconds(850)));
  String hash=user.getResetTokenHash();
  assertEquals(202,browserPost(browser,"forgot-password","{\"email\":\""+email+"\"}").statusCode());
  assertEquals(hash,users.findByEmail(email).orElseThrow().getResetTokenHash());
  assertEquals(400,browserPost(browser,"reset-password","{\"token\":\""+token+"\",\"password\":\"short\"}").statusCode());
  String reset="{\"token\":\""+token+"\",\"password\":\""+replacement+"\"}";
  assertEquals(204,browserPost(browser,"reset-password",reset).statusCode());
  assertEquals(400,browserPost(browser,"reset-password",reset).statusCode());
  for(var login:List.of(first,second)) {
   String access=field(login.body(),"accessToken");
   assertEquals(401,request("GET","/api/v1/auth/me",null,access).statusCode());
   assertEquals("{\"active\":false}",introspect(access,"walletx-finance:integration-test-service-secret-at-least-32-characters").body());
   assertEquals(401,request("POST","/api/v1/auth/refresh","{\"refreshToken\":\""+field(login.body(),"refreshToken")+"\"}",null).statusCode());
  }
  assertEquals(401,request("POST","/api/v1/auth/login",c,null).statusCode());
  assertEquals(200,request("POST","/api/v1/auth/login",credentials(email,replacement),null).statusCode());
  user=users.findByEmail(email).orElseThrow(); assertNull(user.getResetTokenHash());
  user.setResetRequestedAt(java.time.Instant.now().minusSeconds(61)); users.saveAndFlush(user);
  // Clear this test's development mail so the next delivered token is unambiguous.
  try(var paths=java.nio.file.Files.list(RESET_OUTBOX)) { for(var path:paths.toList()) java.nio.file.Files.delete(path); }
  assertEquals(202,browserPost(browser,"forgot-password","{\"email\":\""+email+"\"}").statusCode());
  String expired=deliveredToken(email);
  user=users.findByEmail(email).orElseThrow(); user.setResetExpiresAt(java.time.Instant.now().minusSeconds(1)); users.saveAndFlush(user);
  assertEquals(400,browserPost(browser,"reset-password","{\"token\":\""+expired+"\",\"password\":\""+original+"\"}").statusCode());
 }
 void assertOneHourToken(String response) {
  assertTrue(response.contains("\"expiresIn\":3600"),response);
  var jwt=decoder.decode(field(response,"accessToken"));
  assertEquals(3600,java.time.Duration.between(jwt.getIssuedAt(),jwt.getExpiresAt()).getSeconds());
 }
 HttpResponse<String> introspect(String token,String basicCredentials) throws Exception {
  var b=HttpRequest.newBuilder(URI.create("http://localhost:"+port+"/api/v1/internal/token/introspect"))
   .header("Content-Type","application/x-www-form-urlencoded");
  if(basicCredentials!=null) b.header("Authorization","Basic "+Base64.getEncoder().encodeToString(basicCredentials.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
  return client.send(b.POST(HttpRequest.BodyPublishers.ofString("token="+URLEncoder.encode(token,java.nio.charset.StandardCharsets.UTF_8))).build(),HttpResponse.BodyHandlers.ofString());
 }
 @Test void introspectionIsPrivateAndTracksRevocation() throws Exception {
  String c=credentials("introspection@example.com","correct-password-123");
  assertEquals(201,request("POST","/api/v1/auth/register",registration(c),null).statusCode());
  var login=request("POST","/api/v1/auth/login",c,null);
  String token=field(login.body(),"accessToken");
  String service="walletx-finance:integration-test-service-secret-at-least-32-characters";
  assertEquals(401,introspect(token,null).statusCode());
  assertEquals(401,introspect(token,"walletx-finance:wrong-secret").statusCode());
  assertEquals(401,request("POST","/api/v1/internal/token/introspect","{}",token).statusCode());
  var active=introspect(token,service); assertEquals(200,active.statusCode());
  assertTrue(active.body().contains("\"active\":true"));
  assertTrue(active.body().contains("\"roles\":[\"USER\"]"));
  assertFalse(active.body().contains("password")); assertFalse(active.body().contains("refreshHash"));
  assertEquals("no-store",active.headers().firstValue("Cache-Control").orElse(""));
  var inactive=introspect("not-a-jwt",service); assertEquals(200,inactive.statusCode());
  assertEquals("{\"active\":false}",inactive.body());
  assertEquals("{\"active\":false}",introspect(field(login.body(),"refreshToken"),service).body());
  assertEquals(204,request("POST","/api/v1/auth/logout",null,token).statusCode());
  assertEquals("{\"active\":false}",introspect(token,service).body());
 }
 @Test void lifecycleAndAuthorization() throws Exception {
  String c=credentials("User@example.com","correct-password-123");
  assertEquals(401,request("GET","/welcome",null,null).statusCode());
  assertEquals(201,request("POST","/api/v1/auth/register",registration(c),null).statusCode());
  assertEquals(409,request("POST","/api/v1/auth/register",registration(c),null).statusCode());
  assertEquals(401,request("POST","/api/v1/auth/login",credentials("User@example.com","wrong-password-123"),null).statusCode());
  var login=request("POST","/api/v1/auth/login",c,null); assertEquals(200,login.statusCode());
  assertOneHourToken(login.body());
  assertEquals("no-store",login.headers().firstValue("Cache-Control").orElse(""));
  String access=field(login.body(),"accessToken"),refresh=field(login.body(),"refreshToken");
  assertEquals(200,request("GET","/api/v1/auth/me",null,access).statusCode());
  assertEquals(403,request("GET","/api/v1/admin/status",null,access).statusCode());
  String[] parts=access.split("\\.");
  String bad=parts[0]+"."+parts[1]+"."+(parts[2].startsWith("A")?"B":"A")+parts[2].substring(1);
  assertEquals(401,request("GET","/api/v1/auth/me",null,bad).statusCode());
  String body="{\"refreshToken\":\""+refresh+"\"}";
  var rotated=request("POST","/api/v1/auth/refresh",body,null); assertEquals(200,rotated.statusCode());
  assertOneHourToken(rotated.body());
  assertEquals(401,request("POST","/api/v1/auth/refresh",body,null).statusCode());
  String nextAccess=field(rotated.body(),"accessToken"),nextRefresh=field(rotated.body(),"refreshToken");
  assertEquals(204,request("POST","/api/v1/auth/logout",null,nextAccess).statusCode());
  assertEquals(401,request("GET","/api/v1/auth/me",null,access).statusCode());
  assertEquals(401,request("GET","/api/v1/auth/me",null,nextAccess).statusCode());
  assertEquals(401,request("POST","/api/v1/auth/refresh","{\"refreshToken\":\""+nextRefresh+"\"}",null).statusCode());
 }
 @Test void browserLifecycleUsesHttpOnlyCookiesCsrfAndRotation() throws Exception {
  var cookies=new CookieManager(null,CookiePolicy.ACCEPT_ALL);
  var browser=HttpClient.newBuilder().cookieHandler(cookies).build();
  String base="http://localhost:"+port;
  String c=credentials("browser-"+UUID.randomUUID()+"@example.com","correct-password-123");
  var unsafe=HttpRequest.newBuilder(URI.create(base+"/api/v1/auth/browser/login")).header("Content-Type","application/json").POST(HttpRequest.BodyPublishers.ofString(c)).build();
  assertEquals(403,browser.send(unsafe,HttpResponse.BodyHandlers.ofString()).statusCode());
  var csrf=browser.send(HttpRequest.newBuilder(URI.create(base+"/api/v1/auth/browser/csrf")).GET().build(),HttpResponse.BodyHandlers.ofString());
  assertEquals(200,csrf.statusCode());String csrfToken=field(csrf.body(),"token");
  assertTrue(cookies.getCookieStore().getCookies().stream().anyMatch(v -> v.getName().equals("XSRF-TOKEN")&&v.isHttpOnly()));
  java.util.function.BiFunction<String,String,HttpRequest> post=(path,body)->HttpRequest.newBuilder(URI.create(base+path))
    .header("Content-Type","application/json").header("X-XSRF-TOKEN",csrfToken)
    .POST(body==null?HttpRequest.BodyPublishers.noBody():HttpRequest.BodyPublishers.ofString(body)).build();
  assertEquals(201,browser.send(post.apply("/api/v1/auth/browser/register",registration(c)),HttpResponse.BodyHandlers.ofString()).statusCode());
  var login=browser.send(post.apply("/api/v1/auth/browser/login",c),HttpResponse.BodyHandlers.ofString());
  assertEquals(200,login.statusCode());assertFalse(login.body().contains("refreshToken"));
  assertOneHourToken(login.body());
  var refreshCookie=login.headers().allValues("Set-Cookie").stream().filter(v -> v.startsWith("walletx_refresh=")).findFirst().orElseThrow();
  assertTrue(refreshCookie.contains("HttpOnly"));assertTrue(refreshCookie.contains("SameSite=Lax"));
  String firstRefresh=refreshCookie.split(";",2)[0];String access=field(login.body(),"accessToken");
  assertEquals(200,request("GET","/api/v1/auth/me",null,access).statusCode());
  var rotated=browser.send(post.apply("/api/v1/auth/browser/refresh",null),HttpResponse.BodyHandlers.ofString());
  assertEquals(200,rotated.statusCode());assertFalse(rotated.body().contains("refreshToken"));
  assertOneHourToken(rotated.body());
  assertNotEquals(firstRefresh,rotated.headers().allValues("Set-Cookie").stream().filter(v -> v.startsWith("walletx_refresh=")).findFirst().orElseThrow().split(";",2)[0]);
  String xsrfCookie=cookies.getCookieStore().getCookies().stream().filter(v -> v.getName().equals("XSRF-TOKEN")).findFirst().orElseThrow().getValue();
  var replay=HttpRequest.newBuilder(URI.create(base+"/api/v1/auth/browser/refresh"))
    .header("Cookie",firstRefresh+"; XSRF-TOKEN="+xsrfCookie).header("X-XSRF-TOKEN",csrfToken)
    .POST(HttpRequest.BodyPublishers.noBody()).build();
  assertEquals(401,client.send(replay,HttpResponse.BodyHandlers.ofString()).statusCode());
  var logout=browser.send(post.apply("/api/v1/auth/browser/logout",null),HttpResponse.BodyHandlers.ofString());
  assertEquals(204,logout.statusCode());
  assertTrue(logout.headers().allValues("Set-Cookie").stream().anyMatch(v -> v.contains("walletx_refresh=")&&v.contains("Max-Age=0")));
  assertEquals(401,request("GET","/api/v1/auth/me",null,access).statusCode());
  assertEquals(401,browser.send(post.apply("/api/v1/auth/browser/refresh",null),HttpResponse.BodyHandlers.ofString()).statusCode());
 }
 @Test void validationAndLockout() throws Exception {
  assertEquals(400,request("POST","/api/v1/auth/register",credentials("bad","short"),null).statusCode());
  String c=credentials("locked@example.com","correct-password-123");
  assertEquals(201,request("POST","/api/v1/auth/register",registration(c),null).statusCode());
  for(int i=0;i<5;i++) assertEquals(401,request("POST","/api/v1/auth/login",credentials("locked@example.com","incorrect-password"),null).statusCode());
  assertEquals(401,request("POST","/api/v1/auth/login",c,null).statusCode());
 }
 @Test void rejectsExpiredAndWrongAudienceAndAllowsAdmin() throws Exception {
  String email="admin@example.com", c=credentials(email,"correct-password-123");
  assertEquals(201,request("POST","/api/v1/auth/register",registration(c),null).statusCode());
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
   statement.execute("ALTER TABLE "+legacy+".auth_users DROP COLUMN full_name, DROP COLUMN reset_token_hash, DROP COLUMN reset_expires_at, DROP COLUMN reset_requested_at");
   var userId=UUID.randomUUID(); var sessionId=UUID.randomUUID();
   statement.execute("INSERT INTO "+legacy+".auth_users (id,email,password_hash,role,failed_attempts) VALUES ('"+userId+"','migration@example.com','test-password-hash','USER',2)");
   statement.execute("INSERT INTO "+legacy+".auth_sessions (id,user_id,refresh_hash,expires_at,revoked) VALUES ('"+sessionId+"','"+userId+"','test-refresh-hash',CURRENT_TIMESTAMP+INTERVAL '1 day',false)");
   String beforeUser, beforeSession;
   try(var rows=statement.executeQuery("SELECT to_jsonb(t)::text FROM "+legacy+".auth_users t")) { assertTrue(rows.next()); beforeUser=rows.getString(1); }
   try(var rows=statement.executeQuery("SELECT row_to_json(t)::text FROM "+legacy+".auth_sessions t")) { assertTrue(rows.next()); beforeSession=rows.getString(1); }
   var flyway=org.flywaydb.core.Flyway.configure().dataSource(dataSource).defaultSchema(target).schemas(target)
    .placeholders(Map.of("legacySchema",legacy)).locations("classpath:db/migration").load();
   assertEquals(2,flyway.migrate().migrationsExecuted);
   try(var rows=statement.executeQuery("SELECT to_jsonb(t)::text FROM (SELECT id,email,password_hash,role,failed_attempts,locked_until FROM "+target+".auth_users) t")) { assertTrue(rows.next()); assertEquals(beforeUser,rows.getString(1)); }
   try(var rows=statement.executeQuery("SELECT full_name,reset_token_hash FROM "+target+".auth_users")) { assertTrue(rows.next()); assertNull(rows.getString(1)); assertNull(rows.getString(2)); }
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
