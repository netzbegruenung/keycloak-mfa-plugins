package netzbegruenung.keycloak.authenticator;

import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.events.Details;
import org.keycloak.events.EventType;
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
import org.keycloak.testframework.realm.UserConfig;
import org.keycloak.testframework.realm.UserBuilder;
import org.keycloak.testframework.server.KeycloakServerConfig;
import org.keycloak.testframework.server.KeycloakServerConfigBuilder;
import org.keycloak.testframework.server.KeycloakUrls;
import org.keycloak.testframework.ui.annotations.InjectPage;
import org.keycloak.testframework.ui.annotations.InjectWebDriver;
import org.keycloak.testframework.ui.page.ErrorPage;
import org.keycloak.testframework.ui.page.LoginPage;
import org.keycloak.testframework.ui.webdriver.ManagedWebDriver;

import java.io.InputStream;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * @InjectHttpServer hands back a shared JDK HttpServer bound to 127.0.0.1:8500 (see
 * HttpServerSupplier) that stands in for the SMS gateway ApiSmsService calls out to -
 * an in-process replacement for a MockServer container, reachable from Keycloak whether
 * it runs embedded in this JVM or as a local distribution process, since both are on the
 * same host.
 */
@KeycloakIntegrationTest(config = SmsAuthenticatorFlowTest.ServerConfig.class)
public class SmsAuthenticatorFlowTest {

	private static final String SMS_GATEWAY_PATH = "/sms-authenticator-flow-test/sms";
	private static final Pattern CODE_PATTERN = Pattern.compile("\\b(\\d{6})\\b");

	@InjectRealm
	ManagedRealm managedRealm;

	@InjectUser(config = SmsUserConfig.class, lifecycle = LifeCycle.METHOD)
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
	HttpServer smsGatewayServer;

	// static: @TestSetup only runs once against the class-scoped realm/HTTP context, but
	// JUnit5 creates a fresh test instance per method - an instance field here would leave
	// every instance but the first reading from a queue the shared handler never writes to.
	private static final LinkedBlockingQueue<String> smsRequestBodies = new LinkedBlockingQueue<>();

	@TestSetup
	public void setup() {
		smsGatewayServer.createContext(SMS_GATEWAY_PATH, exchange -> {
			String body;
			try (InputStream is = exchange.getRequestBody()) {
				body = new String(is.readAllBytes(), StandardCharsets.UTF_8);
			}
			smsRequestBodies.add(body);
			exchange.sendResponseHeaders(200, -1);
			exchange.close();
		});

		SmsTestSupport.registerRequiredAction(managedRealm, "mobile_number_config");
		SmsTestSupport.registerRequiredAction(managedRealm, "phone_validation_config");

		Map<String, String> config = new HashMap<>();
		config.put("apiurl", "http://127.0.0.1:8500" + SMS_GATEWAY_PATH);
		config.put("urlencode", "true");
		config.put("messageattribute", "body");
		config.put("receiverattribute", "to");
		config.put("senderattribute", "sender");
		config.put("senderId", "test-sender");
		config.put("countrycode", "");
		config.put("length", "6");
		config.put("ttl", "300");
		SmsTestSupport.setupSmsBrowserFlow(managedRealm, config);
	}

	@BeforeEach
	public void clearState() {
		driver.open(keycloakUrls.getBase());
		driver.cookies().deleteAll();
		events.clear();
		smsRequestBodies.clear();
	}

	@Test
	public void phoneNumberSetupCreatesCredential() throws Exception {
		registerPhoneNumber();

		// PhoneValidationRequiredAction doesn't fire a dedicated UPDATE_CREDENTIAL event of
		// its own (unlike e.g. trusted-device-authenticator) - completing the required
		// action itself is what's observable here; credential creation is verified directly
		// against the admin API below.
		EventAssertion.assertSuccess(events.poll())
			.type(EventType.CUSTOM_REQUIRED_ACTION)
			.userId(user.getId());

		boolean hasMobileNumberCredential = managedRealm.admin().users().get(user.getId())
			.credentials()
			.stream()
			.anyMatch(credential -> "mobile-number".equals(credential.getType()));
		assertTrue(hasMobileNumberCredential, "Expected a mobile-number credential after phone number setup");
	}

	@Test
	public void secondLoginPromptsForSmsCode() throws Exception {
		registerPhoneNumber();
		logout();
		events.clear();

		oauth.openLoginForm();
		loginPage.fillLogin(user.getUsername(), user.getPassword());
		loginPage.submit();

		smsCodePage.assertCurrent();
		smsCodePage.enterCode(awaitSmsCode());
		smsCodePage.submit();

		EventAssertion.assertSuccess(events.poll())
			.type(EventType.LOGIN)
			.userId(user.getId())
			.details(Details.USERNAME, user.getUsername());
	}

	@Test
	public void invalidSmsCodeIsRejectedAndCanBeRetried() throws Exception {
		registerPhoneNumber();
		logout();
		events.clear();

		oauth.openLoginForm();
		loginPage.fillLogin(user.getUsername(), user.getPassword());
		loginPage.submit();

		smsCodePage.assertCurrent();
		String correctCode = awaitSmsCode();
		smsCodePage.enterCode("000000".equals(correctCode) ? "111111" : "000000");
		smsCodePage.submit();

		// Rejected: still on the SMS code page, no successful login event yet.
		smsCodePage.assertCurrent();
		events.clear();

		smsCodePage.enterCode(correctCode);
		smsCodePage.submit();

		EventAssertion.assertSuccess(events.poll())
			.type(EventType.LOGIN)
			.userId(user.getId())
			.details(Details.USERNAME, user.getUsername());
	}

	@Test
	public void expiredSmsCodeIsRejected() throws Exception {
		registerPhoneNumber();
		logout();
		events.clear();

		SmsTestSupport.updateSmsExecutionConfig(managedRealm, Map.of("ttl", "2"));
		try {
			oauth.openLoginForm();
			loginPage.fillLogin(user.getUsername(), user.getPassword());
			loginPage.submit();

			smsCodePage.assertCurrent();
			String code = awaitSmsCode();

			Thread.sleep(3000);

			smsCodePage.enterCode(code);
			smsCodePage.submit();

			// SmsAuthenticator.action() treats an expired code as a terminal failure
			// (createErrorPage), unlike a wrong code which re-challenges the same form.
			errorPage.assertCurrent();
			assertTrue(errorPage.getError().contains("expired"), "Expected an expiry error, got: " + errorPage.getError());
		} finally {
			SmsTestSupport.updateSmsExecutionConfig(managedRealm, Map.of("ttl", "300"));
		}
	}

	private void registerPhoneNumber() throws InterruptedException {
		oauth.openLoginForm();
		loginPage.fillLogin(user.getUsername(), user.getPassword());
		loginPage.submit();

		phoneNumberSetupPage.assertCurrent();
		phoneNumberSetupPage.enterPhoneNumber("+491234567");
		phoneNumberSetupPage.submit();
		// Submitting the phone number fires its own CUSTOM_REQUIRED_ACTION event before the
		// SMS code step's UPDATE_CREDENTIAL event - clear it so callers only see the latter.
		events.clear();

		smsCodePage.assertCurrent();
		smsCodePage.enterCode(awaitSmsCode());
		smsCodePage.submit();
	}

	private void logout() {
		managedRealm.admin().users().get(user.getId()).logout();
	}

	private String awaitSmsCode() throws InterruptedException {
		String body = smsRequestBodies.poll(10, TimeUnit.SECONDS);
		assertNotNull(body, "Expected the SMS gateway stub to receive a request");
		Map<String, String> form = parseFormData(body);
		String message = form.get("body");
		assertThat("Expected the SMS gateway to receive a message body", message, notNullValue());
		Matcher matcher = CODE_PATTERN.matcher(message);
		assertTrue(matcher.find(), "Expected a 6-digit code in the SMS body: " + message);
		return matcher.group(1);
	}

	private static Map<String, String> parseFormData(String body) {
		Map<String, String> result = new HashMap<>();
		for (String pair : body.split("&")) {
			int idx = pair.indexOf('=');
			if (idx > 0) {
				String key = URLDecoder.decode(pair.substring(0, idx), StandardCharsets.UTF_8);
				String value = URLDecoder.decode(pair.substring(idx + 1), StandardCharsets.UTF_8);
				result.put(key, value);
			}
		}
		return result;
	}

	public static class SmsUserConfig implements UserConfig {
		@Override
		public UserBuilder configure(UserBuilder user) {
			return user.username("sms-flow-user")
				.password("password")
				.name("Sms", "Flow")
				.email("sms-flow@example.com")
				.emailVerified(true)
				.requiredActions("mobile_number_config");
		}
	}

	public static class ServerConfig implements KeycloakServerConfig {
		@Override
		public KeycloakServerConfigBuilder configure(KeycloakServerConfigBuilder config) {
			// libphonenumber is bundled into the production provider jar only by the
			// shade-plugin step (see sms-authenticator/pom.xml); dependencyCurrentProject()
			// doesn't go through that, so it must be added separately or
			// PhoneNumberRequiredActionFactory fails to load with NoClassDefFoundError.
			return config.dependencyCurrentProject()
				.dependency("com.googlecode.libphonenumber", "libphonenumber");
		}
	}
}
