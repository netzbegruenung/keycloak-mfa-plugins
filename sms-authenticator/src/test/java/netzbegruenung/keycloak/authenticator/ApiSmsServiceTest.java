package netzbegruenung.keycloak.authenticator;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.microsoft.playwright.BrowserType;
import com.microsoft.playwright.Page;
import com.microsoft.playwright.Playwright;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.representations.idm.AuthenticationExecutionInfoRepresentation;
import org.mockserver.model.HttpRequest;

import java.util.Base64;
import java.util.UUID;

import static netzbegruenung.keycloak.ArrayUtils.getLast;
import static netzbegruenung.keycloak.KeycloakTestUtils.createOrUpdateExecutionConfig;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockserver.model.HttpRequest.request;

public class ApiSmsServiceTest extends AbstractAuthenticatorTest {

	/**
	 * Navigates to the account page, logs in, and waits until the SMS code form is
	 * displayed — at which point Keycloak has already sent the SMS to MockServer.
	 */
	private HttpRequest loginAndCaptureSmsRequest(Page page) {
		page.navigate(container.getAuthServerUrl() + "/realms/test-realm/account");
		page.fill("#username", "test@phasetwo.io");
		page.fill("#password", "test123");
		page.click("#kc-login");
		page.locator("#code").waitFor();
		return getLast(mockServerClient.retrieveRecordedRequests(request().withPath("/sms")));
	}

	private AuthenticationExecutionInfoRepresentation findSmsExecution(RealmResource realm) {
		return realm.flows().getExecutions("Browser with SMS 2FA")
			.stream()
			.filter(e -> "mobile-number-authenticator".equals(e.getProviderId()))
			.findFirst()
			.orElseThrow();
	}

	@Test
	@DisplayName("JSON mode sets Content-Type application/json and sends a JSON body")
	public void jsonModeSendsJsonBody() throws Exception {
		BaseTest.setupSMSAuthenticatorForUser(this);
		final var realm = findRealmByName("test-realm");

		createOrUpdateExecutionConfig(realm, findSmsExecution(realm),
			config -> config.getConfig().put("urlencode", "false"));

		try (final var playwright = Playwright.create();
			 final var browser = playwright.chromium().connect(
				 "ws://%s:%d".formatted(playwrightContainer.getHost(), playwrightContainer.getMappedPort(3000)),
				 new BrowserType.ConnectOptions().setExposeNetwork("*"))) {

			final var smsRequest = loginAndCaptureSmsRequest(browser.newPage());
			final var json = MAPPER.readTree(smsRequest.getBody().getValue().toString());

			assertTrue(smsRequest.getFirstHeader("Content-Type").contains("application/json"));
			assertTrue(json.has("body"));
			assertTrue(json.has("to"));
			assertTrue(json.has("sender"));
		}
	}

	@Test
	@DisplayName("apiTokenInHeader sends the raw token as the Authorization header value")
	public void apiTokenInHeaderSendsRawToken() {
		BaseTest.setupSMSAuthenticatorForUser(this);
		final var realm = findRealmByName("test-realm");

		createOrUpdateExecutionConfig(realm, findSmsExecution(realm), config -> {
			config.getConfig().put("apiTokenInHeader", "true");
			config.getConfig().put("apitoken", "my-raw-token");
		});

		try (final var playwright = Playwright.create();
			 final var browser = playwright.chromium().connect(
				 "ws://%s:%d".formatted(playwrightContainer.getHost(), playwrightContainer.getMappedPort(3000)),
				 new BrowserType.ConnectOptions().setExposeNetwork("*"))) {

			final var smsRequest = loginAndCaptureSmsRequest(browser.newPage());
			assertEquals("my-raw-token", smsRequest.getFirstHeader("Authorization"));
		}
	}

	@Test
	@DisplayName("Basic auth sends a Base64-encoded Authorization header when apiuser is configured")
	public void basicAuthSendsEncodedAuthorizationHeader() {
		BaseTest.setupSMSAuthenticatorForUser(this);
		final var realm = findRealmByName("test-realm");

		createOrUpdateExecutionConfig(realm, findSmsExecution(realm), config -> {
			config.getConfig().put("apiTokenInHeader", "false");
			config.getConfig().put("apiuser", "my-user");
			config.getConfig().put("apitoken", "my-password");
		});

		try (final var playwright = Playwright.create();
			 final var browser = playwright.chromium().connect(
				 "ws://%s:%d".formatted(playwrightContainer.getHost(), playwrightContainer.getMappedPort(3000)),
				 new BrowserType.ConnectOptions().setExposeNetwork("*"))) {

			final var smsRequest = loginAndCaptureSmsRequest(browser.newPage());
			final var expected = "Basic " + Base64.getEncoder().encodeToString("my-user:my-password".getBytes());
			assertEquals(expected, smsRequest.getFirstHeader("Authorization"));
		}
	}

	@Test
	@DisplayName("No Authorization header is sent when neither apiTokenInHeader nor apiuser is set")
	public void noAuthorizationHeaderWhenNeitherOptionIsSet() {
		BaseTest.setupSMSAuthenticatorForUser(this);
		final var realm = findRealmByName("test-realm");

		createOrUpdateExecutionConfig(realm, findSmsExecution(realm), config -> {
			config.getConfig().put("apiTokenInHeader", "false");
			config.getConfig().put("apiuser", "");
		});

		try (final var playwright = Playwright.create();
			 final var browser = playwright.chromium().connect(
				 "ws://%s:%d".formatted(playwrightContainer.getHost(), playwrightContainer.getMappedPort(3000)),
				 new BrowserType.ConnectOptions().setExposeNetwork("*"))) {

			final var smsRequest = loginAndCaptureSmsRequest(browser.newPage());
			final var authHeader = smsRequest.getFirstHeader("Authorization");
			assertTrue(authHeader == null || authHeader.isBlank());
		}
	}

	@Test
	@DisplayName("API token appears in JSON body when apitokenattribute is set and apiTokenInHeader is false")
	public void apiTokenAppearsInJsonBodyWhenApitokenattributeIsSet() throws Exception {
		BaseTest.setupSMSAuthenticatorForUser(this);
		final var realm = findRealmByName("test-realm");

		createOrUpdateExecutionConfig(realm, findSmsExecution(realm), config -> {
			config.getConfig().put("urlencode", "false");
			config.getConfig().put("apiTokenInHeader", "false");
			config.getConfig().put("apiuser", "");
			config.getConfig().put("apitokenattribute", "token");
			config.getConfig().put("apitoken", "my-secret");
		});

		try (final var playwright = Playwright.create();
			 final var browser = playwright.chromium().connect(
				 "ws://%s:%d".formatted(playwrightContainer.getHost(), playwrightContainer.getMappedPort(3000)),
				 new BrowserType.ConnectOptions().setExposeNetwork("*"))) {

			final var smsRequest = loginAndCaptureSmsRequest(browser.newPage());
			final var json = MAPPER.readTree(smsRequest.getBody().getValue().toString());
			assertEquals("my-secret", json.get("token").asText());
		}
	}

	@Test
	@DisplayName("UUID field appears in JSON body when useUuid is enabled")
	public void uuidAppearsInJsonBody() throws Exception {
		BaseTest.setupSMSAuthenticatorForUser(this);
		final var realm = findRealmByName("test-realm");

		createOrUpdateExecutionConfig(realm, findSmsExecution(realm), config -> {
			config.getConfig().put("urlencode", "false");
			config.getConfig().put("useUuid", "true");
			config.getConfig().put("uuidAttribute", "msgid");
		});

		try (final var playwright = Playwright.create();
			 final var browser = playwright.chromium().connect(
				 "ws://%s:%d".formatted(playwrightContainer.getHost(), playwrightContainer.getMappedPort(3000)),
				 new BrowserType.ConnectOptions().setExposeNetwork("*"))) {

			final var smsRequest = loginAndCaptureSmsRequest(browser.newPage());
			final var json = MAPPER.readTree(smsRequest.getBody().getValue().toString());
			assertDoesNotThrow(() -> UUID.fromString(json.get("msgid").asText()));
		}
	}

	@Test
	@DisplayName("UUID field appears in URL-encoded body when useUuid is enabled")
	public void uuidAppearsInUrlEncodedBody() {
		BaseTest.setupSMSAuthenticatorForUser(this);
		final var realm = findRealmByName("test-realm");

		createOrUpdateExecutionConfig(realm, findSmsExecution(realm), config -> {
			config.getConfig().put("urlencode", "true");
			config.getConfig().put("useUuid", "true");
			config.getConfig().put("uuidAttribute", "msgid");
		});

		try (final var playwright = Playwright.create();
			 final var browser = playwright.chromium().connect(
				 "ws://%s:%d".formatted(playwrightContainer.getHost(), playwrightContainer.getMappedPort(3000)),
				 new BrowserType.ConnectOptions().setExposeNetwork("*"))) {

			final var smsRequest = loginAndCaptureSmsRequest(browser.newPage());
			final var params = parseFormData(smsRequest.getBody().getValue().toString());
			assertDoesNotThrow(() -> UUID.fromString(params.get("msgid")));
		}
	}

	@Test
	@DisplayName("Custom jsonTemplate is used as the entire request body")
	public void customJsonTemplateIsUsedAsBody() throws Exception {
		BaseTest.setupSMSAuthenticatorForUser(this);
		final var realm = findRealmByName("test-realm");

		createOrUpdateExecutionConfig(realm, findSmsExecution(realm), config -> {
			config.getConfig().put("urlencode", "false");
			config.getConfig().put("jsonTemplate", "{\"phone\":\"%s\",\"text\":\"%s\"}");
		});

		try (final var playwright = Playwright.create();
			 final var browser = playwright.chromium().connect(
				 "ws://%s:%d".formatted(playwrightContainer.getHost(), playwrightContainer.getMappedPort(3000)),
				 new BrowserType.ConnectOptions().setExposeNetwork("*"))) {

			final var smsRequest = loginAndCaptureSmsRequest(browser.newPage());
			final var json = MAPPER.readTree(smsRequest.getBody().getValue().toString());

			assertTrue(json.has("phone"));
			assertTrue(json.has("text"));
			// Template replaces the default body builder — default fields must not appear
			assertFalse(json.has("sender"));
		}
	}

	// -------------------------------------------------------------------------
	// cleanPhoneNumber tests — each stores a differently-formatted number in the
	// credential and verifies the cleaned value reaches MockServer as the "to" field
	// -------------------------------------------------------------------------

	/** Extracts the URL-decoded "to" field from the URL-encoded SMS request body. */
	private String capturedToField(HttpRequest smsRequest) {
		return parseFormData(smsRequest.getBody().getValue().toString()).get("to");
	}

	@Test
	@DisplayName("cleanPhoneNumber: no transformation when countrycode is empty")
	public void cleanPhoneNumberDoesNothingWithoutCountryCode() {
		BaseTest.setupSMSAuthenticatorForUser(this);
		final var realm = findRealmByName("test-realm");

		createOrUpdateExecutionConfig(realm, findSmsExecution(realm),
			config -> config.getConfig().put("countrycode", ""));

		try (final var playwright = Playwright.create();
			 final var browser = playwright.chromium().connect(
				 "ws://%s:%d".formatted(playwrightContainer.getHost(), playwrightContainer.getMappedPort(3000)),
				 new BrowserType.ConnectOptions().setExposeNetwork("*"))) {

			assertEquals("+36201234567", capturedToField(loginAndCaptureSmsRequest(browser.newPage())));
		}
	}

	@Test
	@DisplayName("cleanPhoneNumber: 36... is normalised to +36...")
	public void cleanPhoneNumberAddsPlusPrefixToNumberStartingWithCountryCode() {
		// Store "36201234567" — missing the leading +
		BaseTest.setupSMSAuthenticatorForUser(this, "36201234567");
		final var realm = findRealmByName("test-realm");

		try (final var playwright = Playwright.create();
			 final var browser = playwright.chromium().connect(
				 "ws://%s:%d".formatted(playwrightContainer.getHost(), playwrightContainer.getMappedPort(3000)),
				 new BrowserType.ConnectOptions().setExposeNetwork("*"))) {

			assertEquals("+36201234567", capturedToField(loginAndCaptureSmsRequest(browser.newPage())));
		}
	}

	@Test
	@DisplayName("cleanPhoneNumber: 0036... is normalised to +36...")
	public void cleanPhoneNumberReplacesDoubleZeroPrefixWithPlus() {
		// Store "0036201234567" — international dialling prefix instead of +
		BaseTest.setupSMSAuthenticatorForUser(this, "0036201234567");
		final var realm = findRealmByName("test-realm");

		try (final var playwright = Playwright.create();
			 final var browser = playwright.chromium().connect(
				 "ws://%s:%d".formatted(playwrightContainer.getHost(), playwrightContainer.getMappedPort(3000)),
				 new BrowserType.ConnectOptions().setExposeNetwork("*"))) {

			assertEquals("+36201234567", capturedToField(loginAndCaptureSmsRequest(browser.newPage())));
		}
	}

	@Test
	@DisplayName("cleanPhoneNumber: +360... is normalised to +36... (extra 0 after country code)")
	public void cleanPhoneNumberRemovesExtraZeroAfterCountryCode() {
		// Store "+360201234567" — spurious 0 between country code and subscriber number
		BaseTest.setupSMSAuthenticatorForUser(this, "+360201234567");
		final var realm = findRealmByName("test-realm");

		try (final var playwright = Playwright.create();
			 final var browser = playwright.chromium().connect(
				 "ws://%s:%d".formatted(playwrightContainer.getHost(), playwrightContainer.getMappedPort(3000)),
				 new BrowserType.ConnectOptions().setExposeNetwork("*"))) {

			assertEquals("+36201234567", capturedToField(loginAndCaptureSmsRequest(browser.newPage())));
		}
	}

	@Test
	@DisplayName("cleanPhoneNumber: 0... is normalised to +36... (national format with leading 0)")
	public void cleanPhoneNumberReplacesLeadingZeroWithCountryCode() {
		// Store "0201234567" — national format, leading 0 should be replaced with +36
		BaseTest.setupSMSAuthenticatorForUser(this, "0201234567");
		final var realm = findRealmByName("test-realm");

		try (final var playwright = Playwright.create();
			 final var browser = playwright.chromium().connect(
				 "ws://%s:%d".formatted(playwrightContainer.getHost(), playwrightContainer.getMappedPort(3000)),
				 new BrowserType.ConnectOptions().setExposeNetwork("*"))) {

			assertEquals("+36201234567", capturedToField(loginAndCaptureSmsRequest(browser.newPage())));
		}
	}

	@Test
	@DisplayName("receiverJsonTemplate formats the receiver phone number value in the JSON body")
	public void receiverJsonTemplateFormatsPhoneNumber() throws Exception {
		BaseTest.setupSMSAuthenticatorForUser(this);
		final var realm = findRealmByName("test-realm");

		createOrUpdateExecutionConfig(realm, findSmsExecution(realm), config -> {
			config.getConfig().put("urlencode", "false");
			config.getConfig().put("receiverJsonTemplate", "[\"%s\"]");
		});

		try (final var playwright = Playwright.create();
			 final var browser = playwright.chromium().connect(
				 "ws://%s:%d".formatted(playwrightContainer.getHost(), playwrightContainer.getMappedPort(3000)),
				 new BrowserType.ConnectOptions().setExposeNetwork("*"))) {

			final var smsRequest = loginAndCaptureSmsRequest(browser.newPage());
			final var json = MAPPER.readTree(smsRequest.getBody().getValue().toString());

			// Default template: "to":"<phone>"; custom template: "to":["<phone>"]
			assertTrue(json.get("to").isArray());
		}
	}
}
