package netzbegruenung.keycloak.authenticator;

import com.microsoft.playwright.BrowserType;
import com.microsoft.playwright.Locator;
import com.microsoft.playwright.Page;
import com.microsoft.playwright.Playwright;
import com.microsoft.playwright.options.AriaRole;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.representations.idm.*;
import org.testcontainers.mockserver.MockServerContainer;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static com.microsoft.playwright.assertions.PlaywrightAssertions.assertThat;
import static netzbegruenung.keycloak.ArrayUtils.getLast;
import static netzbegruenung.keycloak.KeycloakTestUtils.*;
import static org.mockserver.model.HttpRequest.request;


public class BaseTest extends AbstractAuthenticatorTest {

	@Test
	@DisplayName("Test SMS Mobile number setup for user")
	public void setupSMSAuthenticatorForUser() {
		setupSMSAuthenticatorForUser(this);
	}

	/**
	 * This method is called from multiple test methods as well to:
	 *  - set up the realm with the proper flow, required actions, etc
	 *  - create a test user
	 *  - setup the SMS based 2FA for the user
	 *
	 * The most basic call of this method is in `BaseTest::setupSMSAuthenticatorForUser`.
	 * All other calls just use this for setup.
	 * @param testInstance
	 */
	public static void setupSMSAuthenticatorForUser(AbstractAuthenticatorTest testInstance) {
		setupSMSAuthenticatorForUser(testInstance, "+36201234567");
	}

	public static void setupSMSAuthenticatorForUser(AbstractAuthenticatorTest testInstance, String mobileNumber) {
		RealmRepresentation testRealm = testInstance.createRealm(realmRepresentation -> {
			realmRepresentation.setRealm("test-realm");
			realmRepresentation.setEnabled(true);
			realmRepresentation.setLoginWithEmailAllowed(true);
		});
		RealmResource realm = testInstance.getKeycloak().realm(testRealm.getRealm());

		createUser(
			realm,
			userRepresentation -> {
				userRepresentation.setEnabled(true);
				userRepresentation.setUsername("test@phasetwo.io");
				userRepresentation.setEmail("test@phasetwo.io");
				userRepresentation.setEmailVerified(true);
				userRepresentation.setFirstName("Test");
				userRepresentation.setLastName("User");
			},
			credentialRepresentation -> {
				credentialRepresentation.setType(CredentialRepresentation.PASSWORD);
				credentialRepresentation.setValue("test123");
				credentialRepresentation.setTemporary(false);
			}
		);

		final var copiedFlow = copyFlow(realm, "browser", Map.of("newName", "Browser with SMS 2FA"));
		var copiedExecutions = realm.flows().getExecutions(copiedFlow.getAlias());
		final var otpExecution = copiedExecutions.stream().filter(execution -> execution.getDisplayName().contains("Conditional 2FA")).findFirst().orElseThrow();

		final var smsTwoFactorExecution = addExecution(realm, otpExecution, "mobile-number-authenticator", executionInfoRepresentation -> {
			executionInfoRepresentation.setRequirement("ALTERNATIVE");
		});

		createOrUpdateExecutionConfig(realm, smsTwoFactorExecution, executionConfig -> {
			executionConfig.setAlias("sms-2fa");
			executionConfig.getConfig().putAll(
				Map.ofEntries(
					Map.entry("apiurl", "http://mockserver:" + MockServerContainer.PORT + "/sms"),
					Map.entry("urlencode", "true"),
					Map.entry("apiTokenInHeader", "false"),
					Map.entry("apitoken", "secret-api-token"),
					Map.entry("apiuser", "api-user"),
					Map.entry("messageattribute", "body"),
					Map.entry("receiverattribute", "to"),
					Map.entry("senderattribute", "sender"),
					Map.entry("senderId", "senderId"),
					Map.entry("forceSecondFactor", "false"),
					Map.entry("simulation", "false"),
					Map.entry("countrycode", "+36"),
					Map.entry("length", "6"),
					Map.entry("whitelist", "TODO-test-this"),
					Map.entry("ttl", "300"),
					Map.entry("forceRetryOnBadFormat", "false"),
					Map.entry("normalizePhoneNumber", "false"),
					Map.entry("hideResponsePayload", "false"),
					Map.entry("storeInAttribute", "false")
				));
		});

		registerUnregisteredRequiredActionById(realm, "mobile_number_config");
		registerUnregisteredRequiredActionById(realm, "phone_validation_config");


		try (final var playwright = Playwright.create(); final var browser = playwright.chromium().connect("ws://%s:%d".formatted(playwrightContainer.getHost(), playwrightContainer.getMappedPort(3000)), new BrowserType.ConnectOptions().setExposeNetwork("*"));) {
			Page page = browser.newPage();
			page.navigate(container.getAuthServerUrl() + "/realms/" + testRealm.getRealm() + "/account");

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
			if (page.getByText("Please enter your phone number").isVisible()) {
				page.fill("#code", mobileNumber);
				page.locator("input[name='phonenumber']").click();
			}

			assertThat(page.getByRole(AriaRole.HEADING, new Page.GetByRoleOptions().setName("SMS Code"))).isVisible();

			final var sentSmsRequest = getLast(mockServerClient.retrieveRecordedRequests(request().withPath("/sms")));
			final var smsRequestBody = sentSmsRequest.getBody().getValue().toString();
			final var smsData = parseFormData(smsRequestBody);
			final var verificationCode = extractCodeFromBody(smsData.get("body"));

			page.fill("#code", verificationCode);
			page.locator("input[name='login']").click();

			page.getByTestId("page-heading").waitFor();
			if (!page.getByTestId("accountSecurity").isVisible()) {
				page.click("#nav-toggle");
			}
			page.getByTestId("accountSecurity").click();
			page.getByTestId("account-security/signing-in").click();
			assertThat(page.getByText("Mobile Number: ***567")).isVisible();
		}

		testRealm.setBrowserFlow(copiedFlow.getAlias());
		realm.update(testRealm);
	}

}
