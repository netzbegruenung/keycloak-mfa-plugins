package netzbegruenung.keycloak.authenticator.vonage;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import netzbegruenung.keycloak.authenticator.SmsAuthenticator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.events.Details;
import org.keycloak.events.EventType;
import org.keycloak.representations.idm.ConfigPropertyRepresentation;
import org.keycloak.testframework.annotations.InjectEvents;
import org.keycloak.testframework.annotations.InjectHttpServer;
import org.keycloak.testframework.annotations.InjectKeycloakUrls;
import org.keycloak.testframework.annotations.InjectRealm;
import org.keycloak.testframework.annotations.InjectUser;
import org.keycloak.testframework.annotations.KeycloakIntegrationTest;
import org.keycloak.testframework.annotations.TestSetup;
import org.keycloak.testframework.events.EventAssertion;
import org.keycloak.testframework.events.Events;
import org.keycloak.testframework.injection.LifeCycle;
import org.keycloak.testframework.oauth.OAuthClient;
import org.keycloak.testframework.oauth.annotations.InjectOAuthClient;
import org.keycloak.testframework.realm.ManagedRealm;
import org.keycloak.testframework.realm.ManagedUser;
import org.keycloak.testframework.realm.UserBuilder;
import org.keycloak.testframework.realm.UserConfig;
import org.keycloak.testframework.server.KeycloakServerConfig;
import org.keycloak.testframework.server.KeycloakServerConfigBuilder;
import org.keycloak.testframework.server.KeycloakUrls;
import org.keycloak.testframework.ui.annotations.InjectPage;
import org.keycloak.testframework.ui.annotations.InjectWebDriver;
import org.keycloak.testframework.ui.page.ErrorPage;
import org.keycloak.testframework.ui.page.LoginPage;
import org.keycloak.testframework.ui.webdriver.ManagedWebDriver;
import org.keycloak.util.JsonSerialization;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Drives the SMS authenticator with the vonage-verify provider through a browser. The
 * Vonage Verify v2 API is replaced by a stub on the HttpServer of the test framework, which
 * answers like the API specification says: it accepts the code {@link #CODE}, and
 * terminates a request after three wrong codes.
 *
 * This module is installed in Keycloak as a second jar next to sms-authenticator, so these
 * tests also cover that a provider from another jar is found and can add its settings.
 */
@KeycloakIntegrationTest(config = VonageVerifyFlowTest.ServerConfig.class)
public class VonageVerifyFlowTest {

	private static final String VONAGE_PATH = "/vonage-verify-flow-test";
	private static final String VERIFY_PATH = VONAGE_PATH + "/v2/verify";
	private static final String CODE = "424242";
	private static final String WRONG_CODE = "111111";

	@InjectRealm
	ManagedRealm managedRealm;

	@InjectUser(config = VonageUserConfig.class, lifecycle = LifeCycle.METHOD)
	ManagedUser user;

	@InjectWebDriver
	ManagedWebDriver driver;

	@InjectOAuthClient
	OAuthClient oauth;

	@InjectEvents
	Events events;

	@InjectPage
	LoginPage loginPage;

	@InjectPage
	PhoneNumberSetupPage phoneNumberSetupPage;

	@InjectPage
	SmsCodePage smsCodePage;

	@InjectPage
	ErrorPage errorPage;

	@InjectKeycloakUrls
	KeycloakUrls keycloakUrls;

	@InjectHttpServer
	HttpServer vonageServer;

	// static for the same reason as in SmsAuthenticatorFlowTest: the handler is registered
	// once, but JUnit creates a new test instance per method.
	private static final List<Map<String, Object>> startRequests = new CopyOnWriteArrayList<>();
	private static final List<String> authorizations = new CopyOnWriteArrayList<>();
	private static final List<String> checkedCodes = new CopyOnWriteArrayList<>();
	private static final Map<String, AtomicInteger> wrongCodes = new ConcurrentHashMap<>();
	private static volatile int startStatus = 202;

	@TestSetup
	public void setup() {
		vonageServer.createContext(VERIFY_PATH, VonageVerifyFlowTest::handleVonageRequest);

		SmsTestSupport.registerRequiredAction(managedRealm, "mobile_number_config");
		SmsTestSupport.registerRequiredAction(managedRealm, "phone_validation_config");

		Map<String, String> config = new HashMap<>();
		config.put("provider", "vonage-verify");
		config.put("vonageVerifyBaseUrl", "http://127.0.0.1:8500" + VONAGE_PATH);
		config.put("vonageVerifyApiKey", "test-key");
		config.put("vonageVerifyApiSecret", "test-secret");
		config.put("vonageVerifyBrand", "ACME");
		config.put("countrycode", "");
		config.put("length", "6");
		config.put("ttl", "300");
		SmsTestSupport.setupSmsBrowserFlow(managedRealm, config);
	}

	@SuppressWarnings("unchecked")
	private static void handleVonageRequest(HttpExchange exchange) throws IOException {
		String path = exchange.getRequestURI().getPath();
		Map<String, Object> body = JsonSerialization.readValue(
			new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8), Map.class);
		authorizations.add(String.valueOf(exchange.getRequestHeaders().getFirst("Authorization")));

		if (path.equals(VERIFY_PATH)) {
			startRequests.add(body);
			if (startStatus != 202) {
				respond(exchange, startStatus, "{\"title\":\"Conflict\",\"detail\":\"Concurrent verifications to the same number are not allowed.\"}");
				return;
			}
			String requestId = UUID.randomUUID().toString();
			wrongCodes.put(requestId, new AtomicInteger());
			respond(exchange, 202, "{\"request_id\":\"" + requestId + "\"}");
			return;
		}

		String requestId = path.substring(VERIFY_PATH.length() + 1);
		String code = String.valueOf(body.get("code"));
		checkedCodes.add(code);
		AtomicInteger wrong = wrongCodes.get(requestId);
		if (wrong == null) {
			respond(exchange, 404, "{\"title\":\"Not Found\",\"detail\":\"The request ID provided could not be found.\"}");
		} else if (CODE.equals(code)) {
			wrongCodes.remove(requestId);
			respond(exchange, 200, "{\"request_id\":\"" + requestId + "\",\"status\":\"completed\"}");
		} else if (wrong.incrementAndGet() >= 3) {
			wrongCodes.remove(requestId);
			respond(exchange, 410, "{\"title\":\"Invalid Code\",\"detail\":\"An incorrect code has been provided too many times. Workflow terminated.\"}");
		} else {
			respond(exchange, 400, "{\"title\":\"Invalid Code\",\"detail\":\"The code you provided does not match the expected value.\"}");
		}
	}

	private static void respond(HttpExchange exchange, int status, String body) throws IOException {
		byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
		exchange.getResponseHeaders().add("Content-Type", "application/json");
		exchange.sendResponseHeaders(status, bytes.length);
		exchange.getResponseBody().write(bytes);
		exchange.close();
	}

	@BeforeEach
	public void clearState() {
		driver.open(keycloakUrls.getBase());
		driver.cookies().deleteAll();
		events.clear();
		clearVonageRequests();
		wrongCodes.clear();
		startStatus = 202;
	}

	private static void clearVonageRequests() {
		startRequests.clear();
		authorizations.clear();
		checkedCodes.clear();
	}

	@Test
	public void providerFromSecondJarContributesConfigProperties() {
		List<ConfigPropertyRepresentation> properties = managedRealm.admin().flows()
			.getAuthenticatorConfigDescription("mobile-number-authenticator")
			.getProperties();
		List<String> names = properties.stream().map(ConfigPropertyRepresentation::getName).toList();

		ConfigPropertyRepresentation provider = properties.stream()
			.filter(property -> "provider".equals(property.getName()))
			.findFirst()
			.orElseThrow(() -> new AssertionError("Expected a provider property, got: " + names));
		assertEquals(List.of("generic", "vonage-verify"), provider.getOptions());

		assertTrue(names.containsAll(List.of("apiurl", "vonageVerifyApiKey", "vonageVerifyApiSecret", "vonageVerifyBrand",
			"vonageVerifyLocale", "vonageVerifyTemplateId", "vonageVerifyBaseUrl")), "Got: " + names);
		assertTrue(names.indexOf("apiurl") < names.indexOf("vonageVerifyApiKey"),
			"Expected the generic settings before the Vonage settings, got: " + names);
		assertEquals(names.size(), names.stream().distinct().count(), "Expected no duplicate properties, got: " + names);
	}

	@Test
	public void phoneNumberSetupStartsVerificationAndChecksCode() {
		registerPhoneNumber();

		EventAssertion.assertSuccess(events.poll())
			.type(EventType.CUSTOM_REQUIRED_ACTION)
			.userId(user.getId());

		assertEquals(1, startRequests.size(), "Expected one verification request");
		Map<String, Object> start = startRequests.get(0);
		assertEquals("ACME", start.get("brand"));
		assertEquals(6, start.get("code_length"));
		assertEquals(300, start.get("channel_timeout"));
		assertEquals(List.of(Map.of("channel", "sms", "to", "491234567")), start.get("workflow"));
		assertTrue(!start.containsKey("code"), "The code has to be generated by Vonage");
		assertEquals(List.of(CODE), checkedCodes);
		String basic = "Basic " + Base64.getEncoder().encodeToString("test-key:test-secret".getBytes(StandardCharsets.UTF_8));
		assertEquals(List.of(basic, basic), authorizations);

		boolean hasMobileNumberCredential = managedRealm.admin().users().get(user.getId())
			.credentials()
			.stream()
			.anyMatch(credential -> "mobile-number".equals(credential.getType()));
		assertTrue(hasMobileNumberCredential, "Expected a mobile-number credential after phone number setup");
	}

	@Test
	public void loginChecksCodeWithVonage() {
		openSmsCodePage();
		assertEquals(1, startRequests.size(), "Expected one verification request");

		smsCodePage.enterCode(CODE);
		smsCodePage.submit();

		EventAssertion.assertSuccess(events.poll())
			.type(EventType.LOGIN)
			.userId(user.getId())
			.details(Details.USERNAME, user.getUsername());
		assertEquals(List.of(CODE), checkedCodes);
	}

	@Test
	public void wrongCodeIsRejectedAndCanBeRetried() {
		openSmsCodePage();

		smsCodePage.enterCode(WRONG_CODE);
		smsCodePage.submit();

		smsCodePage.assertCurrent();
		EventAssertion.assertError(events.poll())
			.type(EventType.LOGIN_ERROR)
			.error(SmsAuthenticator.INVALID_SMS_CODE)
			.userId(user.getId());
		events.clear();

		smsCodePage.enterCode(CODE);
		smsCodePage.submit();

		EventAssertion.assertSuccess(events.poll())
			.type(EventType.LOGIN)
			.userId(user.getId());
		assertEquals(List.of(WRONG_CODE, CODE), checkedCodes);
		assertEquals(1, startRequests.size(), "Expected a wrong code to keep the verification request");
	}

	@Test
	public void thirdWrongCodeEndsTheVerification() {
		openSmsCodePage();

		for (int attempt = 1; attempt <= 2; attempt++) {
			smsCodePage.enterCode(WRONG_CODE);
			smsCodePage.submit();
			smsCodePage.assertCurrent();
		}
		events.clear();

		smsCodePage.enterCode(WRONG_CODE);
		smsCodePage.submit();

		errorPage.assertCurrent();
		assertTrue(errorPage.getError().contains("expired"), "Expected an expiry error, got: " + errorPage.getError());
		EventAssertion.assertError(events.poll())
			.type(EventType.LOGIN_ERROR)
			.error(SmsAuthenticator.EXPIRED_SMS_CODE)
			.userId(user.getId());
	}

	@Test
	public void refreshDoesNotStartSecondVerification() {
		openSmsCodePage();
		assertEquals(1, startRequests.size(), "Expected one verification request");

		driver.driver().navigate().refresh();

		smsCodePage.assertCurrent();
		assertEquals(1, startRequests.size(), "Expected the open verification request to be kept on refresh");

		smsCodePage.enterCode(CODE);
		smsCodePage.submit();

		EventAssertion.assertSuccess(events.poll())
			.type(EventType.LOGIN)
			.userId(user.getId());
	}

	@Test
	public void failedStartShowsError() {
		registerPhoneNumber();
		logout();
		events.clear();
		clearVonageRequests();
		startStatus = 409;

		oauth.openLoginForm();
		loginPage.fillLogin(user.getUsername(), user.getPassword());
		loginPage.submit();

		errorPage.assertCurrent();
		assertEquals(1, startRequests.size(), "Expected one verification request");
		assertTrue(checkedCodes.isEmpty(), "Expected no code check without a verification request");
	}

	/** Registers a phone number, logs out and logs in again up to the SMS code form. */
	private void openSmsCodePage() {
		registerPhoneNumber();
		logout();
		events.clear();
		clearVonageRequests();

		oauth.openLoginForm();
		loginPage.fillLogin(user.getUsername(), user.getPassword());
		loginPage.submit();
		smsCodePage.assertCurrent();
	}

	private void registerPhoneNumber() {
		oauth.openLoginForm();
		loginPage.fillLogin(user.getUsername(), user.getPassword());
		loginPage.submit();

		phoneNumberSetupPage.assertCurrent();
		phoneNumberSetupPage.enterPhoneNumber("+491234567");
		phoneNumberSetupPage.submit();
		events.clear();

		smsCodePage.assertCurrent();
		smsCodePage.enterCode(CODE);
		smsCodePage.submit();
	}

	private void logout() {
		managedRealm.admin().users().get(user.getId()).logout();
	}

	public static class VonageUserConfig implements UserConfig {
		@Override
		public UserBuilder configure(UserBuilder user) {
			return user.username("vonage-flow-user")
				.password("password")
				.name("Vonage", "Flow")
				.email("vonage-flow@example.com")
				.emailVerified(true)
				.requiredActions("mobile_number_config");
		}
	}

	public static class ServerConfig implements KeycloakServerConfig {
		@Override
		public KeycloakServerConfigBuilder configure(KeycloakServerConfigBuilder config) {
			// This module, plus sms-authenticator and the library it bundles in its jar,
			// like they are installed together in the providers directory.
			return config.dependencyCurrentProject()
				.dependency("netzbegruenung", "sms-authenticator")
				.dependency("com.googlecode.libphonenumber", "libphonenumber");
		}
	}
}
