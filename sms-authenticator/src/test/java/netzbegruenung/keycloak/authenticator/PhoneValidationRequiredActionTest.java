package netzbegruenung.keycloak.authenticator;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.authentication.RequiredActionContext;
import org.keycloak.common.util.Time;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.ThemeManager;
import org.keycloak.models.UserModel;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.theme.Theme;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import jakarta.ws.rs.core.Response;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Properties;

import static netzbegruenung.keycloak.authenticator.PhoneValidationRequiredAction.LAST_OTP_SENT;
import static netzbegruenung.keycloak.authenticator.PhoneValidationRequiredAction.OTP_SEND_COUNT;
import static netzbegruenung.keycloak.authenticator.PhoneValidationRequiredAction.formatWaitHumanReadable;
import static netzbegruenung.keycloak.authenticator.PhoneValidationRequiredAction.requiredSecondsBetweenSends;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class PhoneValidationRequiredActionTest {

	private final PhoneValidationRequiredAction action = new PhoneValidationRequiredAction();

	/** Stands in for user storage, so the read-modify-write of the send counter is exercised for real. */
	private final Map<String, String> userAttributes = new HashMap<>();
	/** Stands in for the auth session notes of one browser session. */
	private final Map<String, String> authNotes = new HashMap<>();

	@Mock private RequiredActionContext context;
	@Mock private UserModel user;
	@Mock private RealmModel realm;
	@Mock private AuthenticationSessionModel authSession;
	@Mock private AuthenticatorConfigModel authenticatorConfig;
	@Mock private LoginFormsProvider forms;
	@Mock private KeycloakSession session;
	@Mock private KeycloakContext keycloakContext;
	@Mock private ThemeManager themeManager;
	@Mock private Theme theme;

	@BeforeEach
	void wireContext() throws Exception {
		when(context.getUser()).thenReturn(user);
		when(context.getRealm()).thenReturn(realm);
		when(context.getAuthenticationSession()).thenReturn(authSession);
		when(context.form()).thenReturn(forms);
		when(context.getSession()).thenReturn(session);
		when(session.theme()).thenReturn(themeManager);
		when(session.getContext()).thenReturn(keycloakContext);
		when(keycloakContext.resolveLocale(any())).thenReturn(Locale.ENGLISH);
		when(themeManager.getTheme(Theme.Type.LOGIN)).thenReturn(theme);
		when(user.getUsername()).thenReturn("alice");
		when(realm.getAuthenticatorConfigByAlias("sms-2fa")).thenReturn(authenticatorConfig);
		when(forms.setAttribute(anyString(), any())).thenReturn(forms);
		when(forms.setError(anyString(), any())).thenReturn(forms);
		when(forms.setError(anyString())).thenReturn(forms);
		// Mocked, not Response.ok().build(): building a real one needs a JAX-RS RuntimeDelegate
		// implementation on the classpath, and nothing here inspects the response.
		when(forms.createForm(anyString())).thenReturn(org.mockito.Mockito.mock(Response.class));

		Properties messages = new Properties();
		messages.setProperty("smsAuthText", "Your SMS code is %1$s and is valid for %2$d minutes.");
		messages.setProperty("smsDebounce1Minute", "1 minute");
		messages.setProperty("smsDebounceNSeconds", "{0} seconds");
		messages.setProperty("smsDebounceJoin2", "{0} {1}");
		when(theme.getEnhancedMessages(any(), any())).thenReturn(messages);

		Map<String, String> config = new HashMap<>();
		config.put("length", "6");
		config.put("ttl", "300");
		config.put("simulation", "true");
		config.put(SmsAuthenticatorFactory.SMS_RESEND_DEBOUNCE_SECONDS, "30");
		config.put(SmsAuthenticatorFactory.SMS_RESEND_DEBOUNCE_MAX_CAP_SECONDS, "240");
		when(authenticatorConfig.getConfig()).thenReturn(config);

		// user attributes
		when(user.getFirstAttribute(anyString())).thenAnswer(i -> userAttributes.get(i.getArgument(0, String.class)));
		when(user.getAttributeStream(anyString())).thenAnswer(i -> {
			String v = userAttributes.get(i.getArgument(0, String.class));
			return v == null ? java.util.stream.Stream.<String>empty() : java.util.stream.Stream.of(v);
		});
		org.mockito.Mockito.doAnswer(i -> userAttributes.put(i.getArgument(0), i.getArgument(1)))
			.when(user).setSingleAttribute(anyString(), anyString());
		org.mockito.Mockito.doAnswer(i -> userAttributes.remove(i.getArgument(0, String.class)))
			.when(user).removeAttribute(anyString());

		// auth session notes
		when(authSession.getAuthNote(anyString())).thenAnswer(i -> authNotes.get(i.getArgument(0, String.class)));
		org.mockito.Mockito.doAnswer(i -> authNotes.put(i.getArgument(0), i.getArgument(1)))
			.when(authSession).setAuthNote(anyString(), anyString());
		org.mockito.Mockito.doAnswer(i -> authNotes.remove(i.getArgument(0, String.class)))
			.when(authSession).removeAuthNote(anyString());

		authNotes.put("mobile_number", "+14155552671");
	}

	@Test
	void firstSendIsAllowedAndRecordsTimestampAndCount() {
		action.requiredActionChallenge(context);

		verify(forms, never()).setError(eq("smsDebounceMessage"), any());
		assertEquals("1", userAttributes.get(OTP_SEND_COUNT));
		assertEquals(authNotes.get(LAST_OTP_SENT), userAttributes.get(LAST_OTP_SENT),
			"send timestamp must be written to both the user and the auth session");
	}

	/**
	 * The regression this whole change exists for: a fresh browser session has no auth note, so the
	 * debounce has to come off the persisted user attribute or it is trivially bypassed by a new tab.
	 */
	@Test
	void debounceIsEnforcedWhenAuthSessionIsFresh() {
		userAttributes.put(LAST_OTP_SENT, String.valueOf(Time.currentTimeSeconds()));
		userAttributes.put(OTP_SEND_COUNT, "1");
		authNotes.remove(LAST_OTP_SENT);

		action.requiredActionChallenge(context);

		verify(forms).setError(eq("smsDebounceMessage"), any());
		assertEquals("1", userAttributes.get(OTP_SEND_COUNT), "a rejected send must not bump the counter");
	}

	@Test
	void sendIsAllowedOnceTheGapHasElapsed() {
		userAttributes.put(LAST_OTP_SENT, String.valueOf(Time.currentTimeSeconds() - 31));
		userAttributes.put(OTP_SEND_COUNT, "1");

		action.requiredActionChallenge(context);

		verify(forms, never()).setError(eq("smsDebounceMessage"), any());
		assertEquals("2", userAttributes.get(OTP_SEND_COUNT));
	}

	/** After 2 sends the gap is 60s, so 31s in is still too early. */
	@Test
	void gapGrowsAfterEachSend() {
		userAttributes.put(LAST_OTP_SENT, String.valueOf(Time.currentTimeSeconds() - 31));
		userAttributes.put(OTP_SEND_COUNT, "2");

		action.requiredActionChallenge(context);

		verify(forms).setError(eq("smsDebounceMessage"), any());
	}

	@Test
	void successfulValidationClearsDebounceState() {
		userAttributes.put(LAST_OTP_SENT, String.valueOf(Time.currentTimeSeconds()));
		userAttributes.put(OTP_SEND_COUNT, "3");
		authNotes.put("code", "123456");
		authNotes.put("ttl", String.valueOf(System.currentTimeMillis() + 60_000));

		org.keycloak.http.HttpRequest request = org.mockito.Mockito.mock(org.keycloak.http.HttpRequest.class);
		jakarta.ws.rs.core.MultivaluedMap<String, String> formParams =
			new jakarta.ws.rs.core.MultivaluedHashMap<>();
		formParams.putSingle("code", "123456");
		when(request.getDecodedFormParameters()).thenReturn(formParams);
		when(context.getHttpRequest()).thenReturn(request);

		SmsAuthCredentialProvider credentialProvider = org.mockito.Mockito.mock(SmsAuthCredentialProvider.class);
		when(session.getProvider(org.keycloak.credential.CredentialProvider.class, "mobile-number"))
			.thenReturn(credentialProvider);
		when(credentialProvider.isConfiguredFor(any(), any(), anyString())).thenReturn(false);

		action.processAction(context);

		verify(context).success();
		assertNull(userAttributes.get(LAST_OTP_SENT));
		assertNull(userAttributes.get(OTP_SEND_COUNT));
		assertNull(authNotes.get(LAST_OTP_SENT));
	}

	/**
	 * The resend button posts to the same endpoint as the code form, and that endpoint routes on the
	 * session code rather than the HTTP method. If processAction does not recognise the resend
	 * parameter it falls through to code validation with no code and reports "invalid SMS code".
	 */
	@Test
	void resendReEntersTheChallengeInsteadOfValidatingAnEmptyCode() {
		authNotes.put("code", "123456");
		authNotes.put("ttl", String.valueOf(System.currentTimeMillis() + 60_000));
		stubFormPost(entry(PhoneValidationRequiredAction.RESEND_PARAM, "Resend Code"), entry("code", ""));

		action.processAction(context);

		verify(forms, never()).setError(eq("smsAuthCodeInvalid"));
		verify(context, never()).success();
		// Re-entered the challenge and sent a fresh code, since no previous send was recorded.
		assertEquals("1", userAttributes.get(OTP_SEND_COUNT));
	}

	/** Resend is not a way around the debounce: it goes through the same gate. */
	@Test
	void resendStillHonoursTheDebounce() {
		userAttributes.put(LAST_OTP_SENT, String.valueOf(Time.currentTimeSeconds()));
		userAttributes.put(OTP_SEND_COUNT, "1");
		stubFormPost(entry(PhoneValidationRequiredAction.RESEND_PARAM, "Resend Code"), entry("code", ""));

		action.processAction(context);

		verify(forms).setError(eq("smsDebounceMessage"), any());
		assertEquals("1", userAttributes.get(OTP_SEND_COUNT));
	}

	@SafeVarargs
	private void stubFormPost(Map.Entry<String, String>... params) {
		jakarta.ws.rs.core.MultivaluedMap<String, String> form = new jakarta.ws.rs.core.MultivaluedHashMap<>();
		for (Map.Entry<String, String> p : params) {
			form.putSingle(p.getKey(), p.getValue());
		}
		org.keycloak.http.HttpRequest request = org.mockito.Mockito.mock(org.keycloak.http.HttpRequest.class);
		when(request.getDecodedFormParameters()).thenReturn(form);
		when(context.getHttpRequest()).thenReturn(request);
	}

	private static Map.Entry<String, String> entry(String k, String v) {
		return new java.util.AbstractMap.SimpleEntry<>(k, v);
	}

	/**
	 * Both defaults are derived from the constants the resolvers fall back to, so they cannot disagree
	 * by construction. What can still break: the settings being dropped from the admin console, a
	 * default that is not a parseable number, or a cap set at or below the baseline — which would make
	 * the very first gap the cap and defeat the backoff entirely.
	 */
	@Test
	void debounceSettingsAreExposedWithUsableDefaults() {
		Map<String, ProviderConfigProperty> byName = new HashMap<>();
		for (ProviderConfigProperty p : new SmsAuthenticatorFactory().getConfigProperties()) {
			byName.put(p.getName(), p);
		}
		ProviderConfigProperty baseline = byName.get(SmsAuthenticatorFactory.SMS_RESEND_DEBOUNCE_SECONDS);
		ProviderConfigProperty cap = byName.get(SmsAuthenticatorFactory.SMS_RESEND_DEBOUNCE_MAX_CAP_SECONDS);
		assertNotNull(baseline, "debounce baseline must stay configurable in the admin console");
		assertNotNull(cap, "debounce cap must stay configurable in the admin console");

		assertEquals(PhoneValidationRequiredAction.DEFAULT_DEBOUNCE_SECONDS,
			Long.parseLong(String.valueOf(baseline.getDefaultValue())));
		assertEquals(PhoneValidationRequiredAction.FALLBACK_DEBOUNCE_MAX_CAP_SECONDS,
			Long.parseLong(String.valueOf(cap.getDefaultValue())));

		assertTrue(PhoneValidationRequiredAction.FALLBACK_DEBOUNCE_MAX_CAP_SECONDS
			> PhoneValidationRequiredAction.DEFAULT_DEBOUNCE_SECONDS,
			"a cap at or below the baseline defeats the exponential backoff");
	}

	@Test
	void gapsDoubleUntilCapped() {
		assertEquals(0, requiredSecondsBetweenSends(0, 30, 240), "no sends yet, no wait");
		assertEquals(30, requiredSecondsBetweenSends(1, 30, 240));
		assertEquals(60, requiredSecondsBetweenSends(2, 30, 240));
		assertEquals(120, requiredSecondsBetweenSends(3, 30, 240));
		assertEquals(240, requiredSecondsBetweenSends(4, 30, 240));
		assertEquals(240, requiredSecondsBetweenSends(5, 30, 240), "capped");
		assertEquals(240, requiredSecondsBetweenSends(500, 30, 240), "no overflow at high send counts");
		assertEquals(0, requiredSecondsBetweenSends(9, 0, 240), "baseline 0 disables debouncing");
	}

	@Test
	void waitTextIsHumanReadable() {
		Properties m = new Properties();
		assertEquals("a moment", formatWaitHumanReadable(0, m));
		assertEquals("1 second", formatWaitHumanReadable(1, m));
		assertEquals("45 seconds", formatWaitHumanReadable(45, m));
		assertEquals("1 minute", formatWaitHumanReadable(60, m));
		assertEquals("1 minute 30 seconds", formatWaitHumanReadable(90, m));
		assertEquals("1 hour", formatWaitHumanReadable(3600, m));
		assertEquals("6 hours", formatWaitHumanReadable(21600, m));
		// sub-minute remainders round up, so the message is never shorter than the real wait
		assertEquals("1 hour 1 minute", formatWaitHumanReadable(3601, m));
	}

}
