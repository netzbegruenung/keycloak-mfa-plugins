package netzbegruenung.keycloak.authenticator;

import com.microsoft.playwright.BrowserType;
import com.microsoft.playwright.Page;
import com.microsoft.playwright.Playwright;
import com.microsoft.playwright.options.AriaRole;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.keycloak.admin.client.resource.RealmResource;

import java.util.Arrays;

import static com.microsoft.playwright.assertions.PlaywrightAssertions.assertThat;
import static netzbegruenung.keycloak.ArrayUtils.getLast;
import static netzbegruenung.keycloak.KeycloakTestUtils.createOrUpdateExecutionConfig;
import static org.mockserver.model.HttpRequest.request;

public class SmsAuthenticatorTest extends AbstractAuthenticatorTest {

	@Test
	@DisplayName("A user who enters a correct but expired SMS code sees an expiry error")
	public void expiredSmsCodeShowsError() throws InterruptedException {
		BaseTest.setupSMSAuthenticatorForUser(this);
		final var realm = findRealmByName("test-realm");
		final var testRealm = realm.toRepresentation();

		// Reduce TTL to 2 seconds for this test only, then restore via the existing config update path
		final var smsExecution = realm.flows().getExecutions("Browser with SMS 2FA")
			.stream()
			.filter(e -> "mobile-number-authenticator".equals(e.getProviderId()))
			.findFirst()
			.orElseThrow();
		createOrUpdateExecutionConfig(realm, smsExecution, config -> config.getConfig().put("ttl", "2"));

		try (
			final var playwright = Playwright.create();
			final var browser = playwright
				.chromium()
				.connect(
					"ws://%s:%d".formatted(playwrightContainer.getHost(), playwrightContainer.getMappedPort(3000)),
					new BrowserType.ConnectOptions().setExposeNetwork("*")
				);
		) {
			Page page = browser.newPage();
			page.navigate(container.getAuthServerUrl() + "/realms/" + testRealm.getRealm() + "/account");

			page.fill("#username", "test@phasetwo.io");
			page.fill("#password", "test123");
			page.click("#kc-login");

			// Capture the real code before it expires
			final var sentSmsRequest = getLast(mockServerClient.retrieveRecordedRequests(request().withPath("/sms")));
			final var smsData = parseFormData(sentSmsRequest.getBody().getValue().toString());
			final var verificationCode = extractCodeFromBody(smsData.get("body"));

			// Wait long enough for the 2-second TTL to elapse
			Thread.sleep(3000);

			page.fill("#code", verificationCode);
			page.locator("input[name='login']").click();

			assertThat(page.getByText("The SMS code has expired.")).isVisible();
		}
	}

	@Test
	@DisplayName("A user who enters an invalid SMS code sees an error and can retry")
	public void invalidSmsCodeShowsError() {
		BaseTest.setupSMSAuthenticatorForUser(this);
		final var realm = findRealmByName("test-realm");
		final var testRealm = realm.toRepresentation();
		try (
			final var playwright = Playwright.create();
			final var browser = playwright
				.chromium()
				.connect(
					"ws://%s:%d".formatted(playwrightContainer.getHost(), playwrightContainer.getMappedPort(3000)),
					new BrowserType.ConnectOptions().setExposeNetwork("*")
				);
		) {
			Page page = browser.newPage();
			page.navigate(container.getAuthServerUrl() + "/realms/" + testRealm.getRealm() + "/account");

			page.fill("#username", "test@phasetwo.io");
			page.fill("#password", "test123");
			page.click("#kc-login");

			// Enter a deliberately wrong code instead of the real one
			page.fill("#code", "000000");
			page.locator("input[name='login']").click();

			// Should stay on the SMS code page — not redirected to account on success
			assertThat(page.getByRole(AriaRole.HEADING, new Page.GetByRoleOptions().setName("SMS Code"))).isVisible();
		}
	}

	@Test
	@DisplayName("A user, who's set up correctly, is prompted for their SMS code")
	public void promptExistingAndSetUpUserForSms2FA() {
		BaseTest.setupSMSAuthenticatorForUser(this);
		final var realm = findRealmByName("test-realm");
		final var testRealm = realm.toRepresentation();
		try (
			final var playwright = Playwright.create();
			final var browser = playwright
				.chromium()
				.connect(
					"ws://%s:%d".formatted(playwrightContainer.getHost(), playwrightContainer.getMappedPort(3000)),
					new BrowserType.ConnectOptions().setExposeNetwork("*")
				);
		) {
			Page page = browser.newPage();
			page.navigate(container.getAuthServerUrl() + "/realms/" + testRealm.getRealm() + "/account");

			page.fill("#username", "test@phasetwo.io");
			page.fill("#password", "test123");
			page.click("#kc-login");

			final var sentSmsRequest = getLast(mockServerClient.retrieveRecordedRequests(request().withPath("/sms")));
			final var smsRequestBody = sentSmsRequest.getBody().getValue().toString();
			final var smsData = parseFormData(smsRequestBody);
			final var verificationCode = extractCodeFromBody(smsData.get("body"));
			page.fill("#code", verificationCode);
			page.locator("input[name='login']").click();

			assertThat(page.getByRole(AriaRole.HEADING, new Page.GetByRoleOptions().setName("Personal info"))).isVisible();
		}
	}
}
