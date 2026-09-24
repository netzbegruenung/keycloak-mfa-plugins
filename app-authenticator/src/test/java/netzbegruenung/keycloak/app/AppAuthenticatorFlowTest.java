package netzbegruenung.keycloak.app;

import com.fasterxml.jackson.databind.JsonNode;
import netzbegruenung.keycloak.app.actiontoken.AppAuthActionTokenHandler;
import netzbegruenung.keycloak.app.actiontoken.AppSetupActionTokenHandler;
import netzbegruenung.keycloak.app.credentials.AppCredentialModel;
import netzbegruenung.keycloak.app.dto.ChallengeDto;
import netzbegruenung.keycloak.app.rest.AppCredentialService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.events.Details;
import org.keycloak.events.EventType;
import org.keycloak.testframework.annotations.InjectEvents;
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
import org.keycloak.testframework.ui.page.LoginPage;
import org.keycloak.testframework.ui.webdriver.ManagedWebDriver;
import org.keycloak.testsuite.util.oauth.AccessTokenResponse;
import org.keycloak.util.JsonSerialization;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.StreamSupport;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * app-authenticator's setup (app-register) and login (app-authenticator) steps are both driven
 * by a real mobile app signing requests, so there's no code the user types the way SMS/OTP
 * work. AppDeviceSimulator plays that missing "mobile app" role over plain HTTP; Selenium is
 * only used for the parts an actual browser does (submitting the username/password form and
 * the app-auth-setup/app-login forms once the device side is done).
 */
@KeycloakIntegrationTest(config = AppAuthenticatorFlowTest.ServerConfig.class)
public class AppAuthenticatorFlowTest {

	@InjectRealm
	ManagedRealm managedRealm;

	@InjectUser(ref = "user", config = AppUserConfig.class, lifecycle = LifeCycle.METHOD)
	ManagedUser user;

	@InjectUser(ref = "secondUser", config = SecondAppUserConfig.class, lifecycle = LifeCycle.METHOD)
	ManagedUser secondUser;

	@InjectWebDriver
	ManagedWebDriver driver;

	@InjectOAuthClient
	OAuthClient oauth;

	@InjectEvents
	Events events;

	@InjectPage
	LoginPage loginPage;

	@InjectPage
	AppAuthSetupPage appAuthSetupPage;

	@InjectPage
	AppLoginPage appLoginPage;

	@InjectKeycloakUrls
	KeycloakUrls keycloakUrls;

	@TestSetup
	public void setup() {
		AppTestSupport.registerRequiredAction(managedRealm, AppRequiredAction.PROVIDER_ID);

		Map<String, String> config = new HashMap<>();
		// simulation=true keeps MessagingServiceFactory on its logging no-op instead of trying
		// to reach Firebase, so the test doesn't need GOOGLE_APPLICATION_CREDENTIALS.
		config.put("simulation", "true");
		config.put("appAuthActionTokenExpiration", "120");
		AppTestSupport.setupAppBrowserFlow(managedRealm, config);
	}

	@BeforeEach
	public void clearState() {
		driver.open(keycloakUrls.getBase());
		driver.cookies().deleteAll();
		events.clear();
	}

	@Test
	public void firstLoginRegistersAppCredential() throws Exception {
		registerDevice();

		boolean hasAppCredential = managedRealm.admin().users().get(user.getId())
			.credentials()
			.stream()
			.anyMatch(credential -> AppCredentialModel.TYPE.equals(credential.getType()));
		assertTrue(hasAppCredential, "Expected an APP_CREDENTIAL credential after setup");
	}

	@Test
	public void secondLoginApprovedViaSignedChallenge() throws Exception {
		AppDeviceSimulator device = registerDevice();
		logout();
		events.clear();

		oauth.openLoginForm();
		loginPage.fillLogin(user.getUsername(), user.getPassword());
		loginPage.submit();

		appLoginPage.assertCurrent();

		ChallengeDto challenge = awaitChallenge(device);
		assertEquals(204, device.respond(challenge, true));

		appLoginPage.submit();

		EventAssertion.assertSuccess(events.poll())
			.type(EventType.LOGIN)
			.userId(user.getId())
			.details(Details.USERNAME, user.getUsername());
	}

	@Test
	public void secondLoginRejectedViaSignedChallenge() throws Exception {
		AppDeviceSimulator device = registerDevice();
		logout();
		events.clear();

		oauth.openLoginForm();
		loginPage.fillLogin(user.getUsername(), user.getPassword());
		loginPage.submit();

		appLoginPage.assertCurrent();

		ChallengeDto challenge = awaitChallenge(device);
		assertEquals(204, device.respond(challenge, false));

		appLoginPage.submit();

		// Rejected: AppAuthenticator.action() re-challenges the same page instead of
		// succeeding, so there's no LOGIN event and the app-login step is shown again,
		// with an app-specific login error event.
		appLoginPage.assertCurrent();
		EventAssertion.assertError(events.poll())
			.type(EventType.LOGIN_ERROR)
			.error(AppAuthenticator.APP_AUTH_REJECTED)
			.userId(user.getId());
	}

	@Test
	public void secondLoginWithInvalidSignatureReportsError() throws Exception {
		AppDeviceSimulator device = registerDevice();
		logout();
		events.clear();

		oauth.openLoginForm();
		loginPage.fillLogin(user.getUsername(), user.getPassword());
		loginPage.submit();

		appLoginPage.assertCurrent();

		ChallengeDto challenge = awaitChallenge(device);
		assertEquals(403, device.respondWithForgedGrant(challenge));

		EventAssertion.assertError(events.poll())
			.type(EventType.EXECUTE_ACTION_TOKEN_ERROR)
			.error(AppAuthActionTokenHandler.APP_AUTH_INVALID_SIGNATURE)
			.userId(user.getId());

		// The forged grant must not log the user in
		appLoginPage.submit();
		appLoginPage.assertCurrent();
	}

	@Test
	public void reregisteringSameDeviceIdReplacesOwnCredential() throws Exception {
		AppDeviceSimulator firstDevice = registerDevice();
		String firstCredentialId = getAppCredentialId(user);
		logout();
		events.clear();

		// The user already has the app credential configured, so "Conditional 2FA" challenges
		// with it first (proving continued possession of the account) before the
		// application-initiated "app-register" action (kc_action - the same AIA mechanism the
		// account console uses) is allowed to run.
		oauth.loginForm().kcAction(AppRequiredAction.PROVIDER_ID).open();
		loginPage.fillLogin(user.getUsername(), user.getPassword());
		loginPage.submit();

		appLoginPage.assertCurrent();
		ChallengeDto loginChallenge = awaitChallenge(firstDevice);
		assertEquals(204, firstDevice.respond(loginChallenge, true));
		appLoginPage.submit();

		appAuthSetupPage.assertCurrent();
		String actionTokenUrl = appAuthSetupPage.getActionTokenUrl();

		// Same device_id as firstDevice (simulating a reinstall), fresh key pair.
		AppDeviceSimulator secondDevice = new AppDeviceSimulator(firstDevice.deviceId());
		assertEquals(201, secondDevice.register(actionTokenUrl), "Expected overwrite registration to succeed");

		appAuthSetupPage.submit();

		EventAssertion.assertSuccess(events.poll())
			.type(EventType.UPDATE_CREDENTIAL)
			.userId(user.getId())
			.details(Details.CREDENTIAL_TYPE, AppCredentialModel.TYPE);

		EventAssertion.assertSuccess(events.poll())
			.type(EventType.CUSTOM_REQUIRED_ACTION)
			.userId(user.getId());

		EventAssertion.assertSuccess(events.poll())
			.type(EventType.LOGIN)
			.userId(user.getId())
			.details(Details.USERNAME, user.getUsername());

		var appCredentials = managedRealm.admin().users().get(user.getId())
			.credentials().stream()
			.filter(credential -> AppCredentialModel.TYPE.equals(credential.getType()))
			.toList();
		assertEquals(1, appCredentials.size(), "Expected exactly one APP_CREDENTIAL after overwrite");
		assertNotEquals(firstCredentialId, appCredentials.get(0).getId(), "Expected a new credential id after overwrite");

		// The new credential is actually usable for login, not just present.
		logout();
		events.clear();

		oauth.openLoginForm();
		loginPage.fillLogin(user.getUsername(), user.getPassword());
		loginPage.submit();

		appLoginPage.assertCurrent();

		ChallengeDto challenge = awaitChallenge(secondDevice);
		assertEquals(204, secondDevice.respond(challenge, true));

		appLoginPage.submit();

		EventAssertion.assertSuccess(events.poll())
			.type(EventType.LOGIN)
			.userId(user.getId())
			.details(Details.USERNAME, user.getUsername());
	}

	@Test
	public void differentUserCannotClaimAnotherUsersDeviceId() throws Exception {
		AppDeviceSimulator device = registerDevice();
		logout();
		events.clear();

		oauth.openLoginForm();
		loginPage.fillLogin(secondUser.getUsername(), secondUser.getPassword());
		loginPage.submit();

		appAuthSetupPage.assertCurrent();
		String actionTokenUrl = appAuthSetupPage.getActionTokenUrl();

		AppDeviceSimulator conflictingDevice = new AppDeviceSimulator(device.deviceId());
		assertEquals(400, conflictingDevice.register(actionTokenUrl), "Expected duplicate device_id registration to be rejected");
		EventAssertion.assertError(events.poll())
			.type(EventType.EXECUTE_ACTION_TOKEN_ERROR)
			.error(AppSetupActionTokenHandler.APP_SETUP_DUPLICATE_DEVICE_ID)
			.userId(secondUser.getId())
			.details("device_id", device.deviceId());

		boolean secondUserHasAppCredential = managedRealm.admin().users().get(secondUser.getId())
			.credentials().stream()
			.anyMatch(credential -> AppCredentialModel.TYPE.equals(credential.getType()));
		assertFalse(secondUserHasAppCredential, "Expected no APP_CREDENTIAL for the second user after a rejected duplicate device_id");
	}

	@Test
	public void setupWithMissingParameterReportsError() throws Exception {
		oauth.openLoginForm();
		loginPage.fillLogin(user.getUsername(), user.getPassword());
		loginPage.submit();

		appAuthSetupPage.assertCurrent();
		String actionTokenUrl = appAuthSetupPage.getActionTokenUrl();

		assertEquals(400, new AppDeviceSimulator().registerWithoutPublicKey(actionTokenUrl));
		EventAssertion.assertError(events.poll())
			.type(EventType.EXECUTE_ACTION_TOKEN_ERROR)
			.error(AppSetupActionTokenHandler.APP_SETUP_INVALID_REQUEST)
			.userId(user.getId());
	}

	@Test
	public void pushTokenUpdateWithInvalidSignatureReportsError() throws Exception {
		AppDeviceSimulator device = registerDevice();
		events.clear();

		// Knows the device_id but not the device's private key
		AppDeviceSimulator impostor = new AppDeviceSimulator(device.deviceId());
		String credentialsUrl = keycloakUrls.getBase() + "/realms/" + managedRealm.getName() + "/app-authenticators/x/credentials";
		assertEquals(401, impostor.updatePushId(credentialsUrl, "attacker-push-id"));

		EventAssertion.assertError(events.poll())
			.type(EventType.LOGIN_ERROR)
			.error(AppCredentialService.APP_DEVICE_INVALID_SIGNATURE)
			.userId(user.getId())
			.details("device_id", device.deviceId());
	}

	@Test
	public void pushTokenUpdateSucceedsForMultipleDevicesWithSameOs() throws Exception {
		AppDeviceSimulator firstDevice = registerDevice();
		logout();
		events.clear();

		// A second device for the same user, added via the app-register kc_action after a
		// Conditional 2FA challenge (same setup as reregisteringSameDeviceIdReplacesOwnCredential),
		// but with its own device_id so this adds a second credential instead of overwriting the
		// first. AppDeviceSimulator.register() always sends device_os=test-os, so both credentials
		// end up sharing the same OS - the precondition for the crash this test guards against.
		oauth.loginForm().kcAction(AppRequiredAction.PROVIDER_ID).open();
		loginPage.fillLogin(user.getUsername(), user.getPassword());
		loginPage.submit();

		appLoginPage.assertCurrent();
		ChallengeDto loginChallenge = awaitChallenge(firstDevice);
		assertEquals(204, firstDevice.respond(loginChallenge, true));
		appLoginPage.submit();

		AppDeviceSimulator secondDevice = completeSetup(new AppDeviceSimulator());

		var appCredentials = managedRealm.admin().users().get(user.getId())
			.credentials().stream()
			.filter(credential -> AppCredentialModel.TYPE.equals(credential.getType()))
			.toList();
		assertEquals(2, appCredentials.size(), "Expected two independent APP_CREDENTIALs sharing the same device OS");

		String credentialsUrl = keycloakUrls.getBase() + "/realms/" + managedRealm.getName() + "/app-authenticators/x/credentials";
		assertEquals(204, firstDevice.updatePushId(credentialsUrl, "push-1"), "Expected the first device's push token update to succeed");
		assertEquals(204, secondDevice.updatePushId(credentialsUrl, "push-2"), "Expected the second device's push token update to succeed despite sharing the first device's OS");
	}

	@Test
	public void accountConsoleShowsDeviceOsAsCredentialLabel() throws Exception {
		registerDevice();

		AccessTokenResponse tokenResponse = oauth.doPasswordGrantRequest(user.getUsername(), user.getPassword());
		assertTrue(tokenResponse.isSuccess(), "Expected the password grant to succeed: "
			+ tokenResponse.getError() + " " + tokenResponse.getErrorDescription());

		// The same REST endpoint the Account Console UI calls to list credentials
		// (AccountRestService#credentials -> AccountCredentialResource#credentialTypes), which
		// builds each entry via CredentialProvider#getCredentialFromModel - this is what's
		// actually being verified here, not just our own createFromCredentialModel in isolation.
		String credentialsUrl = keycloakUrls.getBase() + "/realms/" + managedRealm.getName() + "/account/credentials";
		HttpResponse<String> response = HttpClient.newHttpClient().send(
			HttpRequest.newBuilder(URI.create(credentialsUrl))
				.header("Authorization", "Bearer " + tokenResponse.getAccessToken())
				.header("Accept", "application/json")
				.GET()
				.build(),
			HttpResponse.BodyHandlers.ofString());
		assertEquals(200, response.statusCode(), "Expected the account credentials endpoint to succeed: " + response.body());

		JsonNode credentialTypes = JsonSerialization.readValue(response.body(), JsonNode.class);
		JsonNode appCredentialContainer = StreamSupport.stream(credentialTypes.spliterator(), false)
			.filter(container -> AppCredentialModel.TYPE.equals(container.get("type").asText()))
			.findFirst()
			.orElseThrow(() -> new AssertionError("Expected an APP_CREDENTIAL container in: " + response.body()));

		String userLabel = appCredentialContainer.get("userCredentialMetadatas").get(0).get("credential").get("userLabel").asText();
		assertEquals("test-os", userLabel, "Expected the Account Console to show the device OS as the credential label");
	}

	private AppDeviceSimulator registerDevice() throws Exception {
		oauth.openLoginForm();
		loginPage.fillLogin(user.getUsername(), user.getPassword());
		loginPage.submit();

		return completeSetup(new AppDeviceSimulator());
	}

	private AppDeviceSimulator completeSetup(AppDeviceSimulator device) throws Exception {
		appAuthSetupPage.assertCurrent();
		String actionTokenUrl = appAuthSetupPage.getActionTokenUrl();

		assertEquals(201, device.register(actionTokenUrl), "Expected device registration to succeed");

		appAuthSetupPage.submit();

		EventAssertion.assertSuccess(events.poll())
			.type(EventType.UPDATE_CREDENTIAL)
			.userId(user.getId())
			.details(Details.CREDENTIAL_TYPE, AppCredentialModel.TYPE)
			.details("device_id", device.deviceId());

		EventAssertion.assertSuccess(events.poll())
			.type(EventType.CUSTOM_REQUIRED_ACTION)
			.userId(user.getId());

		EventAssertion.assertSuccess(events.poll())
			.type(EventType.LOGIN)
			.userId(user.getId())
			.details(Details.USERNAME, user.getUsername());

		return device;
	}

	private String getAppCredentialId(ManagedUser managedUser) {
		return managedRealm.admin().users().get(managedUser.getId())
			.credentials().stream()
			.filter(credential -> AppCredentialModel.TYPE.equals(credential.getType()))
			.findFirst()
			.orElseThrow(() -> new IllegalStateException("Expected an APP_CREDENTIAL for user " + managedUser.getId()))
			.getId();
	}

	private ChallengeDto awaitChallenge(AppDeviceSimulator device) throws Exception {
		String challengesUrl = keycloakUrls.getBase() + "/realms/" + managedRealm.getName() + "/challenges";
		for (int i = 0; i < 20; i++) {
			List<ChallengeDto> challenges = device.fetchChallenges(challengesUrl);
			if (!challenges.isEmpty()) {
				return challenges.get(0);
			}
			Thread.sleep(250);
		}
		assertFalse(true, "Expected a pending challenge for the registered device");
		return null;
	}

	private void logout() {
		managedRealm.admin().users().get(user.getId()).logout();
	}

	public static class AppUserConfig implements UserConfig {
		@Override
		public UserBuilder configure(UserBuilder user) {
			return user.username("app-flow-user")
				.password("password")
				.name("App", "Flow")
				.email("app-flow@example.com")
				.emailVerified(true)
				.requiredActions(AppRequiredAction.PROVIDER_ID);
		}
	}

	public static class SecondAppUserConfig implements UserConfig {
		@Override
		public UserBuilder configure(UserBuilder user) {
			return user.username("app-flow-user-2")
				.password("password")
				.name("App", "FlowTwo")
				.email("app-flow-2@example.com")
				.emailVerified(true)
				.requiredActions(AppRequiredAction.PROVIDER_ID);
		}
	}

	public static class ServerConfig implements KeycloakServerConfig {
		@Override
		public KeycloakServerConfigBuilder configure(KeycloakServerConfigBuilder config) {
			return config.dependencyCurrentProject()
				.dependency("org.keycloak.tests", "keycloak-tests-utils-shared");
		}
	}
}
