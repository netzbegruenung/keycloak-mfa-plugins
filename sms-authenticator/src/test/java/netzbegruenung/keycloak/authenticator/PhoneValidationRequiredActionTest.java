package netzbegruenung.keycloak.authenticator;

import jakarta.ws.rs.core.MultivaluedHashMap;
import netzbegruenung.keycloak.authenticator.credentials.SmsAuthCredentialModel;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.keycloak.authentication.RequiredActionContext;
import org.keycloak.credential.CredentialProvider;
import org.keycloak.events.EventBuilder;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.http.HttpRequest;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.SingleUseObjectProvider;
import org.keycloak.models.ThemeManager;
import org.keycloak.models.UserCredentialModel;
import org.keycloak.models.UserModel;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.theme.Theme;

import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Properties;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.RETURNS_SELF;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for the phone validation step's branches the browser flow tests do not reach (missing configuration,
 * cooldown, credential update, attribute storage). SmsCode is the real one, on an in-memory store; the SMS goes
 * through simulation mode.
 */
class PhoneValidationRequiredActionTest {

	private static final String NUMBER = "+491234567";

	private final Map<String, Map<String, String>> entries = new HashMap<>();
	private final Map<String, String> smsConfig = new HashMap<>();
	private final MultivaluedHashMap<String, String> formData = new MultivaluedHashMap<>();
	private final PhoneValidationRequiredAction action = new PhoneValidationRequiredAction();

	private RequiredActionContext context;
	private RealmModel realm;
	private UserModel user;
	private LoginFormsProvider form;
	private SmsAuthCredentialProvider credentialProvider;
	private AuthenticatorConfigModel config;

	@BeforeEach
	void setUp() throws Exception {
		smsConfig.put("simulation", "true");
		config = new AuthenticatorConfigModel();
		config.setConfig(smsConfig);

		context = mock(RequiredActionContext.class);
		realm = mock(RealmModel.class);
		user = mock(UserModel.class);
		form = mock(LoginFormsProvider.class, RETURNS_SELF);
		credentialProvider = mock(SmsAuthCredentialProvider.class);
		KeycloakSession session = mock(KeycloakSession.class);
		AuthenticationSessionModel authSession = mock(AuthenticationSessionModel.class);
		EventBuilder event = mock(EventBuilder.class, RETURNS_SELF);
		HttpRequest request = mock(HttpRequest.class);
		ThemeManager themes = mock(ThemeManager.class);
		Theme theme = mock(Theme.class);
		KeycloakContext keycloakContext = mock(KeycloakContext.class);
		Properties messages = new Properties();
		messages.setProperty("smsAuthText", "Your SMS code is %1$s and is valid for %2$d minutes.");

		when(context.getRealm()).thenReturn(realm);
		when(context.getUser()).thenReturn(user);
		when(context.getSession()).thenReturn(session);
		when(context.getAuthenticationSession()).thenReturn(authSession);
		when(context.form()).thenReturn(form);
		when(context.getEvent()).thenReturn(event);
		when(context.getHttpRequest()).thenReturn(request);
		when(request.getDecodedFormParameters()).thenReturn(formData);
		when(realm.getAuthenticatorConfigByAlias("sms-2fa")).thenReturn(config);
		when(user.getId()).thenReturn("user-1");
		when(user.getUsername()).thenReturn("alice");
		when(authSession.getAuthNote("mobile_number")).thenReturn(NUMBER);
		SingleUseObjectProvider store = InMemorySingleUseObjects.backedBy(entries);
		when(session.singleUseObjects()).thenReturn(store);
		when(session.theme()).thenReturn(themes);
		when(themes.getTheme(Theme.Type.LOGIN)).thenReturn(theme);
		when(theme.getEnhancedMessages(realm, Locale.ENGLISH)).thenReturn(messages);
		when(session.getContext()).thenReturn(keycloakContext);
		when(keycloakContext.resolveLocale(user)).thenReturn(Locale.ENGLISH);
		when(session.getProvider(CredentialProvider.class, "mobile-number")).thenReturn(credentialProvider);
	}

	private String sentCode() {
		return entries.get("sms-authenticator.code.user-1").get("code");
	}

	@Test
	@DisplayName("Without the sms-2fa configuration, the challenge fails")
	void challengeWithoutConfigurationFails() {
		when(realm.getAuthenticatorConfigByAlias("sms-2fa")).thenReturn(null);

		action.requiredActionChallenge(context);

		verify(context).failure();
		verify(context, never()).challenge(any());
	}

	@Test
	@DisplayName("A second challenge inside the cooldown sends nothing and shows the wait")
	void challengeInsideCooldownShowsTheWait() {
		action.requiredActionChallenge(context);
		String firstCode = sentCode();

		action.requiredActionChallenge(context);

		verify(form).setInfo(eq("smsAuthResendCooldown"), any());
		org.junit.jupiter.api.Assertions.assertEquals(firstCode, sentCode());
	}

	@Test
	@DisplayName("Without the sms-2fa configuration, a submitted code fails")
	void processActionWithoutConfigurationFails() {
		formData.putSingle("code", "123456");
		when(realm.getAuthenticatorConfigByAlias("sms-2fa")).thenReturn(null);

		action.processAction(context);

		verify(context).failure();
	}

	@Test
	@DisplayName("A code submitted when none was sent re-runs the challenge, which sends one")
	void codeWithoutSentCodeSendsOne() {
		formData.putSingle("code", "123456");

		action.processAction(context);

		verify(context).challenge(any());
		org.junit.jupiter.api.Assertions.assertNotNull(sentCode());
	}

	@Test
	@DisplayName("A wrong code shows the error on the code page")
	void wrongCodeShowsTheError() {
		action.requiredActionChallenge(context);
		formData.putSingle("code", "wrong");

		action.processAction(context);

		verify(form).setError("smsAuthCodeInvalid");
		verify(context, never()).success();
	}

	@Test
	@DisplayName("A valid code of a user without SMS credential creates it, without storing an attribute by default")
	void validCodeCreatesTheCredential() {
		action.requiredActionChallenge(context);
		formData.putSingle("code", sentCode());
		when(credentialProvider.isConfiguredFor(realm, user, SmsAuthCredentialModel.TYPE)).thenReturn(false);

		action.processAction(context);

		verify(credentialProvider).createCredential(eq(realm), eq(user),
			argThat(model -> NUMBER.equals(model.getSmsAuthenticatorData().getMobileNumber())));
		verify(user, never()).setSingleAttribute(anyString(), anyString());
		verify(context).success();
	}

	@Test
	@DisplayName("A valid code of an enrolled user updates the credential and stores the configured attribute")
	void validCodeUpdatesTheCredentialAndStoresTheAttribute() {
		smsConfig.put("storeInAttribute", "true");
		smsConfig.put("mobileNumberAttribute", "phone");
		action.requiredActionChallenge(context);
		formData.putSingle("code", sentCode());
		when(credentialProvider.isConfiguredFor(realm, user, SmsAuthCredentialModel.TYPE)).thenReturn(true);

		action.processAction(context);

		verify(credentialProvider).updateCredential(eq(realm), eq(user),
			argThat((UserCredentialModel input) -> NUMBER.equals(input.getChallengeResponse())));
		verify(user).setSingleAttribute("phone", NUMBER);
		verify(context).success();
	}

	@Test
	@DisplayName("A configuration removed before the attribute step skips the attribute, the validation succeeds")
	void configurationRemovedBeforeTheAttributeStepSkipsIt() {
		smsConfig.put("storeInAttribute", "true");
		action.requiredActionChallenge(context);
		formData.putSingle("code", sentCode());
		when(realm.getAuthenticatorConfigByAlias("sms-2fa")).thenReturn(config, (AuthenticatorConfigModel) null);

		action.processAction(context);

		verify(user, never()).setSingleAttribute(anyString(), anyString());
		verify(context).success();
	}
}
