package netzbegruenung.keycloak.authenticator;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.microsoft.playwright.BrowserType;
import com.microsoft.playwright.Locator;
import com.microsoft.playwright.Page;
import com.microsoft.playwright.Playwright;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;
import org.testcontainers.mockserver.MockServerContainer;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static com.microsoft.playwright.assertions.PlaywrightAssertions.assertThat;
import static netzbegruenung.keycloak.ArrayUtils.getLast;
import static netzbegruenung.keycloak.KeycloakTestUtils.*;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockserver.model.HttpRequest.request;

public class PhoneNumberRequiredActionTest extends AbstractAuthenticatorTest {

	/**
	 * Creates realm, user, and authentication flow with the mobile-number-authenticator.
	 * configOverrides are merged on top of sensible defaults. Returns the realm resource.
	 */
	private RealmResource setupRealm(Map<String, String> configOverrides) {
		final var testRealm = createRealm(r -> {
			r.setRealm("test-realm");
			r.setEnabled(true);
			r.setLoginWithEmailAllowed(true);
		});
		final var realm = getKeycloak().realm(testRealm.getRealm());

		createUser(
			realm,
			u -> {
				u.setEnabled(true);
				u.setUsername("test@phasetwo.io");
				u.setEmail("test@phasetwo.io");
				u.setEmailVerified(true);
				u.setFirstName("Test");
				u.setLastName("User");
			},
			c -> {
				c.setType(CredentialRepresentation.PASSWORD);
				c.setValue("test123");
				c.setTemporary(false);
			}
		);

		final var copiedFlow = copyFlow(realm, "browser", Map.of("newName", "Browser with SMS 2FA"));
		final var otpExecution = realm.flows().getExecutions(copiedFlow.getAlias())
			.stream()
			.filter(e -> e.getDisplayName().contains("Conditional 2FA"))
			.findFirst()
			.orElseThrow();

		final var smsExecution = addExecution(realm, otpExecution, "mobile-number-authenticator",
			e -> e.setRequirement("ALTERNATIVE"));

		final var config = new HashMap<String, String>();
		config.put("apiurl", "http://mockserver:" + MockServerContainer.PORT + "/sms");
		config.put("urlencode", "true");
		config.put("apiTokenInHeader", "false");
		config.put("apitoken", "secret-api-token");
		config.put("apiuser", "api-user");
		config.put("messageattribute", "body");
		config.put("receiverattribute", "to");
		config.put("senderattribute", "sender");
		config.put("senderId", "senderId");
		config.put("forceSecondFactor", "false");
		config.put("simulation", "false");
		config.put("countrycode", "+36");
		config.put("length", "6");
		config.put("ttl", "300");
		config.put("forceRetryOnBadFormat", "false");
		config.put("normalizePhoneNumber", "false");
		config.put("hideResponsePayload", "false");
		config.put("storeInAttribute", "false");
		config.putAll(configOverrides);

		createOrUpdateExecutionConfig(realm, smsExecution, executionConfig -> {
			executionConfig.setAlias("sms-2fa");
			executionConfig.getConfig().putAll(config);
		});

		registerUnregisteredRequiredActionById(realm, "mobile_number_config");
		registerUnregisteredRequiredActionById(realm, "phone_validation_config");

		return realm;
	}

	/** Navigates to the phone-number setup form via the account console. */
	private void navigateToPhoneSetupForm(Page page) {
		page.navigate(container.getAuthServerUrl() + "/realms/test-realm/account");
		page.fill("#username", "test@phasetwo.io");
		page.fill("#password", "test123");
		page.click("#kc-login");

		page.getByTestId("page-heading").waitFor();
		if (!page.getByTestId("accountSecurity").isVisible()) {
			page.click("#nav-toggle");
		}
		page.getByTestId("accountSecurity").click();
		page.getByTestId("account-security/signing-in").click();
		page.getByTestId("mobile-number/create").click(new Locator.ClickOptions().setForce(true));

		if (page.getByText("Sign in to your account").isVisible()) {
			page.fill("#password", "test123");
			page.locator("input[name='login']").click();
		}
	}

	/** Enters the phone number, captures the resulting SMS code and submits it. */
	private void submitPhoneAndVerifyCode(Page page, String phoneNumber) {
		page.fill("#code", phoneNumber);
		page.locator("input[name='phonenumber']").click();

		final var sentSmsRequest = getLast(mockServerClient.retrieveRecordedRequests(request().withPath("/sms")));
		final var smsData = parseFormData(sentSmsRequest.getBody().getValue().toString());
		final var verificationCode = extractCodeFromBody(smsData.get("body"));

		page.fill("#code", verificationCode);
		page.locator("input[name='login']").click();

		page.getByTestId("page-heading").waitFor();
	}

	@Test
	@DisplayName("Phone number is normalised via E164 and stored as a mobile-number credential")
	public void normalizedPhoneNumberIsSavedAsCredential() throws JsonProcessingException {
		// normalizePhoneNumber=true exercises formatPhoneNumber(); "+36201234567" is a valid
		// Hungarian mobile number that comes out of E164 formatting unchanged.
		final var realm = setupRealm(Map.of("normalizePhoneNumber", "true"));

		try (final var playwright = Playwright.create();
			 final var browser = playwright.chromium().connect(
				 "ws://%s:%d".formatted(playwrightContainer.getHost(), playwrightContainer.getMappedPort(3000)),
				 new BrowserType.ConnectOptions().setExposeNetwork("*"))) {

			final var page = browser.newPage();
			navigateToPhoneSetupForm(page);
			submitPhoneAndVerifyCode(page, "+36201234567");
		}

		final var userId = realm.users().search("test@phasetwo.io").get(0).getId();
		final var credentials = realm.users().get(userId).credentials();
		final var mobileCredential = credentials.stream().filter(c -> "mobile-number".equals(c.getType())).findFirst();
		assertTrue(
			mobileCredential.isPresent(),
			"Expected a mobile-number credential to be stored for the user"
		);
		final var credentialData = MAPPER.readTree(mobileCredential.get().getCredentialData());
		assertEquals("+36201234567", credentialData.get("mobileNumber").asText());
	}

	@Test
	@DisplayName("forceSecondFactor=true triggers phone setup as a required action on the next login")
	public void forceSecondFactorTriggersPhoneSetupOnLogin() throws JsonProcessingException {
		// evaluateTriggers() checks forceSecondFactor and adds mobile_number_config
		// to the user's required actions when they have no existing 2FA credential.
		setupRealm(Map.of("forceSecondFactor", "true"));

		try (final var playwright = Playwright.create();
			 final var browser = playwright.chromium().connect(
				 "ws://%s:%d".formatted(playwrightContainer.getHost(), playwrightContainer.getMappedPort(3000)),
				 new BrowserType.ConnectOptions().setExposeNetwork("*"))) {

			final var page = browser.newPage();
			page.navigate(container.getAuthServerUrl() + "/realms/test-realm/account");
			page.fill("#username", "test@phasetwo.io");
			page.fill("#password", "test123");
			page.click("#kc-login");

			// evaluateTriggers fires → mobile_number_config required action added →
			// phone number form is shown before the user reaches the account console.
			page.locator("input[name='phonenumber']").waitFor();

			submitPhoneAndVerifyCode(page, "+36201234567");
		}

		final var realm = findRealmByName("test-realm");
		final var userId = realm.users().search("test@phasetwo.io").get(0).getId();
		final var credentials = realm.users().get(userId).credentials();
		assertTrue(
			credentials.stream().anyMatch(c -> "mobile-number".equals(c.getType())),
			"Expected a mobile-number credential after forceSecondFactor triggered phone setup"
		);
	}

	@Test
	@DisplayName("A user who holds the whitelist role is not prompted for phone setup even when forceSecondFactor=true")
	public void whitelistedUserSkipsPhoneSetupEnforcement() {
		final var realm = setupRealm(Map.of(
			"forceSecondFactor", "true",
			"whitelist", "sms-exempt"
		));

		// Create the realm role and assign it to the user
		final var roleRep = new RoleRepresentation();
		roleRep.setName("sms-exempt");
		realm.roles().create(roleRep);

		final var userId = realm.users().search("test@phasetwo.io").get(0).getId();
		final var savedRole = realm.roles().get("sms-exempt").toRepresentation();
		realm.users().get(userId).roles().realmLevel().add(List.of(savedRole));

		createUser(
			realm,
			u -> {
				u.setEnabled(true);
				u.setUsername("test-non-whitelisted@phasetwo.io");
				u.setEmail("test-non-whitelisted@phasetwo.io");
				u.setEmailVerified(true);
				u.setFirstName("Test");
				u.setLastName("User");
			},
			c -> {
				c.setType(CredentialRepresentation.PASSWORD);
				c.setValue("test123");
				c.setTemporary(false);
			}
		);

		try (final var playwright = Playwright.create();
			 final var browser = playwright.chromium().connect(
				 "ws://%s:%d".formatted(playwrightContainer.getHost(), playwrightContainer.getMappedPort(3000)),
				 new BrowserType.ConnectOptions().setExposeNetwork("*"))) {

			final var page = browser.newPage();
			page.navigate(container.getAuthServerUrl() + "/realms/test-realm/account");
			page.fill("#username", "test@phasetwo.io");
			page.fill("#password", "test123");
			page.click("#kc-login");

			// evaluateTriggers sees the whitelist role on the user and returns early —
			// the phone setup required action must not be added and the user lands
			// directly on the account console.
			page.getByTestId("page-heading").waitFor();
			assertThat(page.locator("input[name='phonenumber']")).not().isVisible();
		}

		try (final var playwright = Playwright.create();
			 final var browser = playwright.chromium().connect(
				 "ws://%s:%d".formatted(playwrightContainer.getHost(), playwrightContainer.getMappedPort(3000)),
				 new BrowserType.ConnectOptions().setExposeNetwork("*"))) {

			final var page = browser.newPage();
			page.navigate(container.getAuthServerUrl() + "/realms/test-realm/account");
			page.fill("#username", "test-non-whitelisted@phasetwo.io");
			page.fill("#password", "test123");
			page.click("#kc-login");

			// evaluateTriggers sees the whitelist role on the user and returns early —
			// the phone setup required action must be added and the user lands
			// directly on the phone-number setup page.
			assertThat(page.locator("input[name='phonenumber']")).isVisible();
		}
	}

	@Test
	@DisplayName("Country code dropdown appears when countryCodeList is set; phone is assembled from country code and local number")
	public void countryCodeDropdownIsShownAndPhoneCombinedWithLocalNumber() throws JsonProcessingException {
		// getCountryCodeList() builds the list from countryCodeList config and passes it to the
		// template. processAction() prepends the selected country_code to the local number.
		setupRealm(Map.of("countryCodeList", "HU,DE"));

		try (final var playwright = Playwright.create();
			 final var browser = playwright.chromium().connect(
				 "ws://%s:%d".formatted(playwrightContainer.getHost(), playwrightContainer.getMappedPort(3000)),
				 new BrowserType.ConnectOptions().setExposeNetwork("*"))) {

			final var page = browser.newPage();
			navigateToPhoneSetupForm(page);

			// The country-code select must be present when countryCodeList is configured
			assertThat(page.locator("#country-code-select")).isVisible();

			// Select Hungary (+36) and enter only the subscriber number (no country prefix)
			page.selectOption("#country-code-select", "+36");
			page.fill("#code", "201234567");
			page.locator("input[name='phonenumber']").click();

			final var sentSmsRequest = getLast(mockServerClient.retrieveRecordedRequests(request().withPath("/sms")));
			final var smsData = parseFormData(sentSmsRequest.getBody().getValue().toString());
			final var verificationCode = extractCodeFromBody(smsData.get("body"));

			page.fill("#code", verificationCode);
			page.locator("input[name='login']").click();

			page.getByTestId("page-heading").waitFor();
		}

		final var realm = findRealmByName("test-realm");
		final var userId = realm.users().search("test@phasetwo.io").get(0).getId();
		final var credentials = realm.users().get(userId).credentials();
		final var mobileCredential = credentials.stream()
			.filter(c -> "mobile-number".equals(c.getType()))
			.findFirst();
		assertTrue(mobileCredential.isPresent(), "Expected a mobile-number credential");
		// processAction: countryCode "+36" + local "201234567" → "+36201234567"
		final var credentialData = MAPPER.readTree(mobileCredential.get().getCredentialData());
		assertEquals("+36201234567", credentialData.get("mobileNumber").asText());
	}

	@Test
	@DisplayName("forceRetryOnBadFormat=true re-challenges with an error when the phone number cannot be parsed")
	public void forceRetryOnBadFormatShowsErrorForUnparsablePhoneNumber() {
		// normalizePhoneNumber=true triggers formatPhoneNumber(). A lone "+" strips to "+"
		// after the non-digit filter, which causes a NumberParseException. With
		// forceRetryOnBadFormat=true, handleInvalidNumber() is called and the error
		// message "numberFormatFailedToParse" is rendered on the form.
		setupRealm(Map.of(
			"normalizePhoneNumber", "true",
			"forceRetryOnBadFormat", "true"
		));

		try (final var playwright = Playwright.create();
			 final var browser = playwright.chromium().connect(
				 "ws://%s:%d".formatted(playwrightContainer.getHost(), playwrightContainer.getMappedPort(3000)),
				 new BrowserType.ConnectOptions().setExposeNetwork("*"))) {

			final var page = browser.newPage();
			navigateToPhoneSetupForm(page);

			// "+" is a single character that satisfies the HTML5 pattern [0-9\+\-\.\ ]
			// but cannot be parsed as a valid phone number by libphonenumber.
			page.fill("#code", "+");
			page.locator("input[name='phonenumber']").click();

			assertThat(page.getByText("Failed to parse the phone number, please enter it again.")).isVisible();
		}
	}

	@Test
	@DisplayName("forceRetryOnBadFormat=true re-challenges with an error when the phone number is parseable but not a valid number")
	public void forceRetryOnBadFormatShowsErrorForInvalidPhoneNumber() {
		// "+3620123" passes phoneNumberUtil.parse() (syntactically valid E164) but
		// fails isValidNumber() because the subscriber part is too short for Hungary.
		// This exercises the numberFormatNumberInvalid branch, distinct from the
		// NumberParseException branch tested above.
		setupRealm(Map.of(
			"normalizePhoneNumber", "true",
			"forceRetryOnBadFormat", "true"
		));

		try (final var playwright = Playwright.create();
			 final var browser = playwright.chromium().connect(
				 "ws://%s:%d".formatted(playwrightContainer.getHost(), playwrightContainer.getMappedPort(3000)),
				 new BrowserType.ConnectOptions().setExposeNetwork("*"))) {

			final var page = browser.newPage();
			navigateToPhoneSetupForm(page);

			page.fill("#code", "20123");
			page.locator("input[name='phonenumber']").click();

			assertThat(page.getByText("Phone number invalid, please enter it again.")).isVisible();
		}
	}

	@Test
	@DisplayName("numberTypeFilters=MOBILE rejects a valid Hungarian landline with a numberFormatNoMatchingFilters error")
	public void numberTypeFilterRejectsLandlineWhenMobileFilterIsSet() {
		// +3629123456 is a valid Hungarian FIXED_LINE number — it passes parse() and
		// isValidNumber(), but getNumberType() returns FIXED_LINE which does not match
		// the MOBILE filter, triggering the numberFormatNoMatchingFilters error path.
		// Filters are separated by "##" (Splitter.on("##") in the source).
		setupRealm(Map.of(
			"normalizePhoneNumber", "true",
			"forceRetryOnBadFormat", "true",
			"numberTypeFilters", "MOBILE"
		));

		try (final var playwright = Playwright.create();
			 final var browser = playwright.chromium().connect(
				 "ws://%s:%d".formatted(playwrightContainer.getHost(), playwrightContainer.getMappedPort(3000)),
				 new BrowserType.ConnectOptions().setExposeNetwork("*"))) {

			final var page = browser.newPage();
			navigateToPhoneSetupForm(page);

			page.fill("#code", "+3629123456");
			page.locator("input[name='phonenumber']").click();

			assertThat(page.getByText("Phone number format is not allowed. Please use a regular mobile or fixed line number.")).isVisible();
		}
	}

	@Test
	@DisplayName("numberTypeFilters=FIXED_LINE rejects a valid Hungarian mobile number with a numberFormatNoMatchingFilters error")
	public void numberTypeFilterRejectsLandlineWhenFixedLineFilterIsSet() {
		// +36201234567 is a valid Hungarian MOBILE number — it passes parse() and
		// isValidNumber(), but getNumberType() returns FIXED_LINE which does not match
		// the MOBILE filter, triggering the numberFormatNoMatchingFilters error path.
		// Filters are separated by "##" (Splitter.on("##") in the source).
		setupRealm(Map.of(
			"normalizePhoneNumber", "true",
			"forceRetryOnBadFormat", "true",
			"numberTypeFilters", "FIXED_LINE"
		));

		try (final var playwright = Playwright.create();
			 final var browser = playwright.chromium().connect(
				 "ws://%s:%d".formatted(playwrightContainer.getHost(), playwrightContainer.getMappedPort(3000)),
				 new BrowserType.ConnectOptions().setExposeNetwork("*"))) {

			final var page = browser.newPage();
			navigateToPhoneSetupForm(page);

			page.fill("#code", "+36201234567");
			page.locator("input[name='phonenumber']").click();

			assertThat(page.getByText("Phone number format is not allowed. Please use a regular mobile or fixed line number.")).isVisible();
		}
	}

	@Test
	@DisplayName("numberTypeFilters=MOBILE accepts a valid Hungarian mobile number and stores the credential")
	public void numberTypeFilterAcceptsMobileWhenMobileFilterIsSet() throws JsonProcessingException {
		// +36201234567 is classified as MOBILE by libphonenumber, so it passes the
		// MOBILE type filter and the credential is stored normally.
		final var realm = setupRealm(Map.of(
			"normalizePhoneNumber", "true",
			"numberTypeFilters", "MOBILE"
		));

		try (final var playwright = Playwright.create();
			 final var browser = playwright.chromium().connect(
				 "ws://%s:%d".formatted(playwrightContainer.getHost(), playwrightContainer.getMappedPort(3000)),
				 new BrowserType.ConnectOptions().setExposeNetwork("*"))) {

			final var page = browser.newPage();
			navigateToPhoneSetupForm(page);
			submitPhoneAndVerifyCode(page, "+36201234567");
		}

		final var userId = realm.users().search("test@phasetwo.io").get(0).getId();
		final var credentials = realm.users().get(userId).credentials();
		final var mobileCredential = credentials.stream().filter(c -> "mobile-number".equals(c.getType())).findFirst();
		assertTrue(mobileCredential.isPresent(), "Expected a mobile-number credential after the mobile number passed the type filter");
		final var credentialData = MAPPER.readTree(mobileCredential.get().getCredentialData());
		assertEquals("+36201234567", credentialData.get("mobileNumber").asText());
	}

	@Test
	@DisplayName("numberTypeFilters=FIXED_LINE accepts a valid Hungarian landline and stores the credential")
	public void numberTypeFilterAcceptsFixedLineWhenMobileFilterIsSet() throws JsonProcessingException {
		// +36201234567 is classified as MOBILE by libphonenumber, so it passes the
		// MOBILE type filter and the credential is stored normally.
		final var realm = setupRealm(Map.of(
			"normalizePhoneNumber", "true",
			"numberTypeFilters", "FIXED_LINE"
		));

		try (final var playwright = Playwright.create();
			 final var browser = playwright.chromium().connect(
				 "ws://%s:%d".formatted(playwrightContainer.getHost(), playwrightContainer.getMappedPort(3000)),
				 new BrowserType.ConnectOptions().setExposeNetwork("*"))) {

			final var page = browser.newPage();
			navigateToPhoneSetupForm(page);
			submitPhoneAndVerifyCode(page, "+3629123456");
		}

		final var userId = realm.users().search("test@phasetwo.io").get(0).getId();
		final var credentials = realm.users().get(userId).credentials();
		final var mobileCredential = credentials.stream().filter(c -> "mobile-number".equals(c.getType())).findFirst();
		assertTrue(mobileCredential.isPresent(), "Expected a mobile-number credential after the mobile number passed the type filter");
		final var credentialData = MAPPER.readTree(mobileCredential.get().getCredentialData());
		assertEquals("+3629123456", credentialData.get("mobileNumber").asText());
	}
}
