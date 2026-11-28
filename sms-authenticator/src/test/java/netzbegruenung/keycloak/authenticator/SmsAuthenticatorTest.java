package netzbegruenung.keycloak.authenticator;

import jakarta.ws.rs.core.MultivaluedHashMap;
import netzbegruenung.keycloak.authenticator.credentials.SmsAuthCredentialModel;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.credential.CredentialModel;
import org.keycloak.credential.CredentialProvider;
import org.keycloak.events.EventBuilder;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.http.HttpRequest;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.SingleUseObjectProvider;
import org.keycloak.models.SubjectCredentialManager;
import org.keycloak.models.ThemeManager;
import org.keycloak.models.UserModel;
import org.keycloak.services.managers.BruteForceProtector;
import org.keycloak.theme.Theme;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.RETURNS_SELF;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for the login SMS step's branches the browser flow tests do not reach: number resolution between
 * credential and attribute, attribute-only users, brute-force protection, every verification outcome. SmsCode is
 * the real one, on an in-memory store; the SMS goes through simulation mode.
 */
class SmsAuthenticatorTest {

	private static final String CREDENTIAL_NUMBER = "+491111111";

	private final Map<String, Map<String, String>> entries = new HashMap<>();
	private final Map<String, String> smsConfig = new HashMap<>();
	private final MultivaluedHashMap<String, String> formData = new MultivaluedHashMap<>();
	private final SmsAuthenticator authenticator = new SmsAuthenticator();

	private AuthenticationFlowContext context;
	private KeycloakSession session;
	private RealmModel realm;
	private UserModel user;
	private SubjectCredentialManager credentials;
	private BruteForceProtector bruteForce;
	private AuthenticatorConfigModel config;
	private CredentialModel credential;

	@BeforeEach
	void setUp() throws Exception {
		smsConfig.put("simulation", "true");
		config = new AuthenticatorConfigModel();
		config.setConfig(smsConfig);
		credential = SmsAuthCredentialModel.createSmsAuthenticator(CREDENTIAL_NUMBER);

		context = mock(AuthenticationFlowContext.class);
		session = mock(KeycloakSession.class);
		realm = mock(RealmModel.class);
		user = mock(UserModel.class);
		credentials = mock(SubjectCredentialManager.class);
		bruteForce = mock(BruteForceProtector.class);
		LoginFormsProvider form = mock(LoginFormsProvider.class, RETURNS_SELF);
		EventBuilder event = mock(EventBuilder.class, RETURNS_SELF);
		HttpRequest request = mock(HttpRequest.class);
		ThemeManager themes = mock(ThemeManager.class);
		Theme theme = mock(Theme.class);
		KeycloakContext keycloakContext = mock(KeycloakContext.class);
		SingleUseObjectProvider store = InMemorySingleUseObjects.backedBy(entries);
		Properties messages = new Properties();
		messages.setProperty("smsAuthText", "Your SMS code is %1$s and is valid for %2$d minutes.");

		when(context.getAuthenticatorConfig()).thenReturn(config);
		when(context.getSession()).thenReturn(session);
		when(context.getRealm()).thenReturn(realm);
		when(context.getUser()).thenReturn(user);
		when(context.form()).thenReturn(form);
		when(context.getEvent()).thenReturn(event);
		when(context.getHttpRequest()).thenReturn(request);
		when(request.getDecodedFormParameters()).thenReturn(formData);
		when(user.getId()).thenReturn("user-1");
		when(user.getUsername()).thenReturn("alice");
		when(user.credentialManager()).thenReturn(credentials);
		when(credentials.getStoredCredentialsByTypeStream(SmsAuthCredentialModel.TYPE))
			.thenAnswer(call -> Stream.of(credential));
		when(session.singleUseObjects()).thenReturn(store);
		when(session.getProvider(BruteForceProtector.class)).thenReturn(bruteForce);
		when(session.theme()).thenReturn(themes);
		when(themes.getTheme(Theme.Type.LOGIN)).thenReturn(theme);
		when(theme.getEnhancedMessages(realm, Locale.ENGLISH)).thenReturn(messages);
		when(session.getContext()).thenReturn(keycloakContext);
		when(keycloakContext.resolveLocale(user)).thenReturn(Locale.ENGLISH);
	}

	private void attribute(String name, String... values) {
		when(user.getAttributeStream(name)).thenAnswer(call -> Arrays.stream(values));
	}

	private void noCredential() {
		when(credentials.getStoredCredentialsByTypeStream(SmsAuthCredentialModel.TYPE))
			.thenAnswer(call -> Stream.empty());
	}

	private String sentCode() {
		return entries.get("sms-authenticator.code.user-1").get("code");
	}

	// --- number resolution -------------------------------------------------------------------------------------

	@Test
	@DisplayName("Without storeInAttribute the credential's number is used")
	void withoutStoreInAttributeTheCredentialIsUsed() {
		attribute("mobile_number", "+492222222");

		assertEquals(CREDENTIAL_NUMBER, SmsAuthenticator.resolveMobileNumber(config, user));
	}

	@Test
	@DisplayName("With storeInAttribute the attribute wins, formatting characters dropped")
	void theAttributeWinsWithStoreInAttribute() {
		smsConfig.put("storeInAttribute", "true");
		attribute("mobile_number", "+49 (222) 222-2.22");

		assertEquals("+49222222222", SmsAuthenticator.resolveMobileNumber(config, user));
	}

	@Test
	@DisplayName("Null and blank attribute values are skipped")
	void nullAndBlankAttributeValuesAreSkipped() {
		smsConfig.put("storeInAttribute", "true");
		attribute("mobile_number", null, "  ", "+492222222");

		assertEquals("+492222222", SmsAuthenticator.resolveMobileNumber(config, user));
	}

	@Test
	@DisplayName("An empty attribute falls back to the credential")
	void anEmptyAttributeFallsBackToTheCredential() {
		smsConfig.put("storeInAttribute", "true");
		attribute("mobile_number");

		assertEquals(CREDENTIAL_NUMBER, SmsAuthenticator.resolveMobileNumber(config, user));
	}

	@Test
	@DisplayName("An attribute that is not a phone number is ignored")
	void aNonPhoneAttributeIsIgnored() {
		smsConfig.put("storeInAttribute", "true");
		attribute("mobile_number", "call me maybe");

		assertEquals(CREDENTIAL_NUMBER, SmsAuthenticator.resolveMobileNumber(config, user));
	}

	@Test
	@DisplayName("Without credential and attribute there is no number")
	void withoutAnySourceThereIsNoNumber() {
		smsConfig.put("storeInAttribute", "true");
		attribute("mobile_number");
		noCredential();

		assertNull(SmsAuthenticator.resolveMobileNumber(config, user));
	}

	@Test
	@DisplayName("A missing configuration, or one without settings, means no attribute")
	void missingConfigurationMeansNoAttribute() {
		AuthenticatorConfigModel withoutSettings = new AuthenticatorConfigModel();
		withoutSettings.setConfig(null);

		assertEquals(CREDENTIAL_NUMBER, SmsAuthenticator.resolveMobileNumber(null, user));
		assertEquals(CREDENTIAL_NUMBER, SmsAuthenticator.resolveMobileNumber(withoutSettings, user));
	}

	// --- configuredFor -----------------------------------------------------------------------------------------

	@Test
	@DisplayName("A user with only a valid attribute is configured when storeInAttribute is on")
	void attributeOnlyUserIsConfigured() {
		SmsAuthCredentialProvider provider = mock(SmsAuthCredentialProvider.class);
		when(session.getProvider(CredentialProvider.class, SmsAuthCredentialProviderFactory.PROVIDER_ID)).thenReturn(provider);
		when(realm.getAuthenticatorConfigByAlias("sms-2fa")).thenReturn(config);
		smsConfig.put("storeInAttribute", "true");
		attribute("mobile_number", "+492222222");

		assertTrue(authenticator.configuredFor(session, realm, user));
	}

	@Test
	@DisplayName("Without credential, a user is not configured if the attribute is unused or empty")
	void userWithoutCredentialOrAttributeIsNotConfigured() {
		SmsAuthCredentialProvider provider = mock(SmsAuthCredentialProvider.class);
		when(session.getProvider(CredentialProvider.class, SmsAuthCredentialProviderFactory.PROVIDER_ID)).thenReturn(provider);
		when(realm.getAuthenticatorConfigByAlias("sms-2fa")).thenReturn(config);
		attribute("mobile_number");

		assertFalse(authenticator.configuredFor(session, realm, user));
		smsConfig.put("storeInAttribute", "true");
		assertFalse(authenticator.configuredFor(session, realm, user));
	}

	// --- brute force -------------------------------------------------------------------------------------------

	@Test
	@DisplayName("A user locked by brute-force protection gets no code")
	void lockedUserGetsNoCode() {
		when(realm.isBruteForceProtected()).thenReturn(true);
		when(bruteForce.isTemporarilyDisabled(session, realm, user)).thenReturn(true);

		authenticator.authenticate(context);

		verify(context).failureChallenge(eq(AuthenticationFlowError.USER_TEMPORARILY_DISABLED), any());
		assertTrue(entries.isEmpty());
	}

	@Test
	@DisplayName("A user locked by brute-force protection cannot submit a code")
	void lockedUserCannotSubmitACode() {
		when(realm.isBruteForceProtected()).thenReturn(true);
		when(bruteForce.isTemporarilyDisabled(session, realm, user)).thenReturn(true);
		formData.putSingle("code", "123456");

		authenticator.action(context);

		verify(context).failureChallenge(eq(AuthenticationFlowError.USER_TEMPORARILY_DISABLED), any());
		verify(context, never()).success();
	}

	@Test
	@DisplayName("In a protected realm, a wrong code counts as an OTP failure")
	void wrongCodeCountsInAProtectedRealm() {
		when(realm.isBruteForceProtected()).thenReturn(true);
		authenticator.authenticate(context);
		formData.putSingle("code", "wrong");

		authenticator.action(context);

		verify(bruteForce).failedLogin(eq(realm), eq(user), any(), any(), eq(Set.of("otp")));
		verify(context).failureChallenge(eq(AuthenticationFlowError.INVALID_CREDENTIALS), any());
	}

	@Test
	@DisplayName("In an unprotected realm, a wrong code is not counted")
	void wrongCodeIsNotCountedInAnUnprotectedRealm() {
		authenticator.authenticate(context);
		formData.putSingle("code", "wrong");

		authenticator.action(context);

		verify(bruteForce, never()).failedLogin(any(), any(), any(), any(), any());
		verify(context).failureChallenge(eq(AuthenticationFlowError.INVALID_CREDENTIALS), any());
	}

	// --- send and verification outcomes ------------------------------------------------------------------------

	@Test
	@DisplayName("Without any number, the step fails with an internal error")
	void withoutNumberTheStepFails() {
		noCredential();

		authenticator.authenticate(context);

		verify(context).failureChallenge(eq(AuthenticationFlowError.INTERNAL_ERROR), any());
		assertTrue(entries.isEmpty());
	}

	@Test
	@DisplayName("A code submitted when none was sent sends one")
	void codeWithoutSentCodeSendsOne() {
		formData.putSingle("code", "123456");

		authenticator.action(context);

		verify(context).challenge(any());
		assertTrue(entries.containsKey("sms-authenticator.code.user-1"));
	}

	@Test
	@DisplayName("An expired code fails with EXPIRED_CODE")
	void expiredCodeFails() {
		entries.put("sms-authenticator.code.user-1", new HashMap<>(Map.of(
			"code", "123456", "expiresAt", Long.toString(System.currentTimeMillis() - 1000L), "attempts", "0")));
		formData.putSingle("code", "123456");

		authenticator.action(context);

		verify(context).failureChallenge(eq(AuthenticationFlowError.EXPIRED_CODE), any());
	}

	@Test
	@DisplayName("The right code succeeds")
	void theRightCodeSucceeds() {
		authenticator.authenticate(context);
		formData.putSingle("code", sentCode());

		authenticator.action(context);

		verify(context).success();
	}
}
