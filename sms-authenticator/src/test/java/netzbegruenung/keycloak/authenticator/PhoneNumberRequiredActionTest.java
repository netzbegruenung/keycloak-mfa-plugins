package netzbegruenung.keycloak.authenticator;

import jakarta.ws.rs.core.MultivaluedHashMap;
import netzbegruenung.keycloak.authenticator.credentials.SmsAuthCredentialModel;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.keycloak.authentication.RequiredActionContext;
import org.keycloak.credential.CredentialModel;
import org.keycloak.credential.CredentialProvider;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.http.HttpRequest;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.SubjectCredentialManager;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserProvider;
import org.keycloak.models.credential.OTPCredentialModel;
import org.keycloak.sessions.AuthenticationSessionModel;

import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.RETURNS_SELF;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for the phone number step: 2FA enforcement and auto-enrolment (evaluateTriggers), the country list,
 * and every check of a submitted number (normalisation, validity, region allowlist, type filters, uniqueness).
 */
class PhoneNumberRequiredActionTest {

	private static final String FRENCH_MOBILE = "+33612345678";

	private final Map<String, String> smsConfig = new HashMap<>();
	private final Map<String, String> notes = new HashMap<>();
	private final Set<String> sessionRequiredActions = new HashSet<>();
	private final MultivaluedHashMap<String, String> formData = new MultivaluedHashMap<>();
	private final PhoneNumberRequiredAction action = new PhoneNumberRequiredAction();

	private RequiredActionContext context;
	private RealmModel realm;
	private UserModel user;
	private SubjectCredentialManager credentials;
	private UserProvider users;
	private SmsAuthCredentialProvider credentialProvider;
	private LoginFormsProvider form;
	private AuthenticatorConfigModel config;

	@BeforeEach
	void setUp() {
		config = new AuthenticatorConfigModel();
		config.setConfig(smsConfig);

		context = mock(RequiredActionContext.class);
		realm = mock(RealmModel.class);
		user = mock(UserModel.class);
		credentials = mock(SubjectCredentialManager.class);
		users = mock(UserProvider.class);
		credentialProvider = mock(SmsAuthCredentialProvider.class);
		form = mock(LoginFormsProvider.class, RETURNS_SELF);
		KeycloakSession session = mock(KeycloakSession.class);
		KeycloakContext keycloakContext = mock(KeycloakContext.class);
		AuthenticationSessionModel authSession = mock(AuthenticationSessionModel.class);
		HttpRequest request = mock(HttpRequest.class);

		when(context.getRealm()).thenReturn(realm);
		when(context.getUser()).thenReturn(user);
		when(context.getSession()).thenReturn(session);
		when(context.getAuthenticationSession()).thenReturn(authSession);
		when(context.form()).thenReturn(form);
		when(context.getHttpRequest()).thenReturn(request);
		when(request.getDecodedFormParameters()).thenReturn(formData);
		when(realm.getAuthenticatorConfigByAlias("sms-2fa")).thenReturn(config);
		when(user.getUsername()).thenReturn("alice");
		when(user.credentialManager()).thenReturn(credentials);
		when(credentials.getStoredCredentialsByTypeStream(SmsAuthCredentialModel.TYPE)).thenAnswer(call -> Stream.empty());
		when(credentials.getStoredCredentialsStream()).thenAnswer(call -> Stream.empty());
		when(user.getRequiredActionsStream()).thenAnswer(call -> Stream.empty());
		when(session.users()).thenReturn(users);
		when(session.getContext()).thenReturn(keycloakContext);
		when(keycloakContext.resolveLocale(user)).thenReturn(Locale.ENGLISH);
		when(session.getProvider(CredentialProvider.class, SmsAuthCredentialProviderFactory.PROVIDER_ID))
			.thenReturn(credentialProvider);
		when(authSession.getAuthNote(anyString())).thenAnswer(call -> notes.get(call.<String>getArgument(0)));
		doAnswer(call -> notes.put(call.getArgument(0), call.getArgument(1)))
			.when(authSession).setAuthNote(anyString(), any());
		when(authSession.getRequiredActions()).thenAnswer(call -> new HashSet<>(sessionRequiredActions));
	}

	private void attribute(String name, String... values) {
		when(user.getAttributeStream(name)).thenAnswer(call -> Arrays.stream(values));
	}

	private void submit(String number) {
		formData.putSingle("mobile_number", number);
	}

	private void assertAccepted(String expectedNumber) {
		assertEquals(expectedNumber, notes.get("mobile_number"));
		verify(context).success();
	}

	private void assertRefusedWith(String error) {
		verify(form).setError(error);
		verify(context).challenge(any());
		verify(context, never()).success();
		assertNull(notes.get("mobile_number"));
	}

	// --- evaluateTriggers --------------------------------------------------------------------------------------

	@Test
	@DisplayName("Without the sms-2fa configuration nothing is enforced")
	void withoutConfigurationNothingIsEnforced() {
		when(realm.getAuthenticatorConfigByAlias("sms-2fa")).thenReturn(null);

		action.evaluateTriggers(context);

		verify(user, never()).addRequiredAction(anyString());
	}

	@Test
	@DisplayName("Without enableByDefault and forceSecondFactor nothing happens")
	void withDefaultsNothingHappens() {
		action.evaluateTriggers(context);

		verify(credentialProvider, never()).createCredential(any(), any(), any());
		verify(user, never()).addRequiredAction(anyString());
	}

	@Test
	@DisplayName("enableByDefault enrols a user from the first non-blank attribute value")
	void enableByDefaultEnrolsFromTheAttribute() {
		smsConfig.put("enableByDefault", "true");
		attribute("mobile_number", null, " ", FRENCH_MOBILE);

		action.evaluateTriggers(context);

		verify(credentialProvider).createCredential(eq(realm), eq(user),
			argThat(model -> FRENCH_MOBILE.equals(model.getSmsAuthenticatorData().getMobileNumber())));
	}

	@Test
	@DisplayName("enableByDefault without attribute value enrols nobody")
	void enableByDefaultWithoutAttributeEnrolsNobody() {
		smsConfig.put("enableByDefault", "true");
		attribute("mobile_number");

		action.evaluateTriggers(context);

		verify(credentialProvider, never()).createCredential(any(), any(), any());
	}

	@Test
	@DisplayName("enableByDefault leaves an enrolled user alone")
	void enableByDefaultLeavesEnrolledUsersAlone() {
		smsConfig.put("enableByDefault", "true");
		CredentialModel enrolled = SmsAuthCredentialModel.createSmsAuthenticator(FRENCH_MOBILE);
		when(credentials.getStoredCredentialsByTypeStream(SmsAuthCredentialModel.TYPE))
			.thenAnswer(call -> Stream.of(enrolled));

		action.evaluateTriggers(context);

		verify(credentialProvider, never()).createCredential(any(), any(), any());
	}

	@Test
	@DisplayName("forceSecondFactor adds the phone number step and the input placeholder")
	void forceSecondFactorAddsThePhoneNumberStep() {
		smsConfig.put("forceSecondFactor", "true");
		smsConfig.put("mobileInputFieldPlaceholder", "+33 6 ...");

		action.evaluateTriggers(context);

		verify(user).addRequiredAction(PhoneNumberRequiredAction.PROVIDER_ID);
		assertEquals("+33 6 ...", notes.get("mobileInputFieldPlaceholder"));
	}

	@Test
	@DisplayName("forceSecondFactor skips users with the whitelist role")
	void forceSecondFactorSkipsWhitelistedUsers() {
		smsConfig.put("forceSecondFactor", "true");
		smsConfig.put("whitelist", "no-2fa");
		RoleModel role = mock(RoleModel.class);
		when(realm.getRole("no-2fa")).thenReturn(role);
		when(user.hasRole(role)).thenReturn(true);

		action.evaluateTriggers(context);

		verify(user, never()).addRequiredAction(anyString());
	}

	@Test
	@DisplayName("forceSecondFactor still applies to users without the whitelist role")
	void forceSecondFactorAppliesToOtherUsers() {
		smsConfig.put("forceSecondFactor", "true");
		smsConfig.put("whitelist", "no-2fa");
		RoleModel role = mock(RoleModel.class);
		when(realm.getRole("no-2fa")).thenReturn(role);

		action.evaluateTriggers(context);

		verify(user).addRequiredAction(PhoneNumberRequiredAction.PROVIDER_ID);
	}

	@Test
	@DisplayName("forceSecondFactor still applies when the whitelist role does not exist")
	void forceSecondFactorAppliesWhenTheWhitelistRoleIsMissing() {
		smsConfig.put("forceSecondFactor", "true");
		smsConfig.put("whitelist", "missing-role");

		action.evaluateTriggers(context);

		verify(user).addRequiredAction(PhoneNumberRequiredAction.PROVIDER_ID);
	}

	@Test
	@DisplayName("forceSecondFactor skips users who already have a second factor")
	void forceSecondFactorSkipsUsersWithASecondFactor() {
		smsConfig.put("forceSecondFactor", "true");
		CredentialModel otp = new CredentialModel();
		otp.setType(OTPCredentialModel.TYPE);
		when(credentials.getStoredCredentialsStream()).thenAnswer(call -> Stream.of(otp));

		action.evaluateTriggers(context);

		verify(user, never()).addRequiredAction(anyString());
	}

	@Test
	@DisplayName("forceSecondFactor skips a session that already asks for a 2FA set-up")
	void forceSecondFactorSkipsPendingSessionActions() {
		smsConfig.put("forceSecondFactor", "true");
		sessionRequiredActions.add(UserModel.RequiredAction.CONFIGURE_TOTP.name());

		action.evaluateTriggers(context);

		verify(user, never()).addRequiredAction(anyString());
	}

	@Test
	@DisplayName("forceSecondFactor skips a user who already has a 2FA set-up pending")
	void forceSecondFactorSkipsPendingUserActions() {
		smsConfig.put("forceSecondFactor", "true");
		when(user.getRequiredActionsStream())
			.thenAnswer(call -> Stream.of(UserModel.RequiredAction.UPDATE_PASSWORD.name()));

		action.evaluateTriggers(context);

		verify(user, never()).addRequiredAction(anyString());
	}

	// --- country list ------------------------------------------------------------------------------------------

	@Test
	@DisplayName("The country list has one entry per valid code, invalid codes are skipped")
	void countryListSkipsInvalidCodes() {
		smsConfig.put("countryCodeList", "fr, DE,X");

		List<Map<String, String>> countries = action.getCountryCodeList(context);

		assertEquals(2, countries.size());
		assertEquals("+33", countries.get(0).get("code"));
		assertEquals("France", countries.get(0).get("name"));
		assertEquals("🇫🇷", countries.get(0).get("emoji"));
		assertEquals("+49", countries.get(1).get("code"));
	}

	// --- processAction -----------------------------------------------------------------------------------------

	@Test
	@DisplayName("Without configuration, the selected country code is prepended and the number accepted")
	void withoutConfigurationTheCountryCodeIsPrepended() {
		when(realm.getAuthenticatorConfigByAlias("sms-2fa")).thenReturn(null);
		submit("06 12 34 56 78");
		formData.putSingle("country_code", "+33");

		action.processAction(context);

		assertAccepted(FRENCH_MOBILE);
		verify(context.getAuthenticationSession()).addRequiredAction(PhoneValidationRequiredAction.PROVIDER_ID);
	}

	@Test
	@DisplayName("A configuration without settings behaves like no configuration")
	void configurationWithoutSettingsBehavesLikeNone() {
		config.setConfig(null);
		submit("+33 6 12 34 56 78");

		action.processAction(context);

		assertAccepted(FRENCH_MOBILE);
	}

	@Test
	@DisplayName("normalizePhoneNumber stores the E.164 form, using the configured country")
	void normalizationStoresE164() {
		smsConfig.put("normalizePhoneNumber", "true");
		smsConfig.put("countrycode", "+33");
		submit("06 12 34 56 78");

		action.processAction(context);

		assertAccepted(FRENCH_MOBILE);
	}

	@Test
	@DisplayName("An unreadable country code falls back to Germany")
	void unreadableCountryCodeFallsBackToGermany() {
		smsConfig.put("normalizePhoneNumber", "true");
		smsConfig.put("countrycode", "France");
		submit("0176 1234567");

		action.processAction(context);

		assertAccepted("+491761234567");
	}

	@Test
	@DisplayName("An unparseable number is refused when forceRetryOnBadFormat is on")
	void unparseableNumberIsRefused() {
		smsConfig.put("normalizePhoneNumber", "true");
		smsConfig.put("forceRetryOnBadFormat", "true");
		submit("abc");

		action.processAction(context);

		assertRefusedWith("numberFormatFailedToParse");
	}

	@Test
	@DisplayName("An invalid number is refused when forceRetryOnBadFormat is on")
	void invalidNumberIsRefused() {
		smsConfig.put("normalizePhoneNumber", "true");
		smsConfig.put("forceRetryOnBadFormat", "true");
		submit("+33123");

		action.processAction(context);

		assertRefusedWith("numberFormatNumberInvalid");
	}

	@Test
	@DisplayName("An invalid number passes unchanged when forceRetryOnBadFormat is off")
	void invalidNumberPassesWithoutForceRetry() {
		smsConfig.put("normalizePhoneNumber", "true");
		submit("+33123");

		action.processAction(context);

		assertAccepted("+33123");
	}

	@Test
	@DisplayName("A number outside the allowed regions is refused")
	void numberOutsideTheAllowedRegionsIsRefused() {
		smsConfig.put("normalizePhoneNumber", "true");
		smsConfig.put("forceRetryOnBadFormat", "true");
		smsConfig.put("allowedRegions", "DE##AT");
		submit(FRENCH_MOBILE);

		action.processAction(context);

		assertRefusedWith("numberFormatRegionNotAllowed");
	}

	@Test
	@DisplayName("Allowed regions are compared case-insensitively, comma or ## separated")
	void allowedRegionsAreCaseInsensitive() {
		smsConfig.put("normalizePhoneNumber", "true");
		smsConfig.put("forceRetryOnBadFormat", "true");
		smsConfig.put("allowedRegions", "DE, fr");
		submit(FRENCH_MOBILE);

		action.processAction(context);

		assertAccepted(FRENCH_MOBILE);
	}

	@Test
	@DisplayName("An allowedRegions key without value allows every region")
	void allowedRegionsWithoutValueAllowsAll() {
		smsConfig.put("normalizePhoneNumber", "true");
		smsConfig.put("allowedRegions", null);
		submit(FRENCH_MOBILE);

		action.processAction(context);

		assertAccepted(FRENCH_MOBILE);
	}

	@Test
	@DisplayName("A number whose type matches no filter is refused")
	void numberTypeOutsideTheFiltersIsRefused() {
		smsConfig.put("normalizePhoneNumber", "true");
		smsConfig.put("forceRetryOnBadFormat", "true");
		smsConfig.put("numberTypeFilters", "FIXED_LINE");
		submit(FRENCH_MOBILE);

		action.processAction(context);

		assertRefusedWith("numberFormatNoMatchingFilters");
	}

	@Test
	@DisplayName("A number whose type matches a filter is accepted")
	void numberTypeMatchingAFilterIsAccepted() {
		smsConfig.put("normalizePhoneNumber", "true");
		smsConfig.put("forceRetryOnBadFormat", "true");
		smsConfig.put("numberTypeFilters", "FIXED_LINE##MOBILE");
		submit(FRENCH_MOBILE);

		action.processAction(context);

		assertAccepted(FRENCH_MOBILE);
	}

	@Test
	@DisplayName("An unknown type filter disables type filtering")
	void unknownTypeFilterDisablesFiltering() {
		smsConfig.put("normalizePhoneNumber", "true");
		smsConfig.put("forceRetryOnBadFormat", "true");
		smsConfig.put("numberTypeFilters", "FIXED_LINE##BOGUS");
		submit(FRENCH_MOBILE);

		action.processAction(context);

		assertAccepted(FRENCH_MOBILE);
	}

	@Test
	@DisplayName("A configuration removed while formatting leaves the number as typed")
	void configurationRemovedWhileFormattingKeepsTheNumber() {
		smsConfig.put("normalizePhoneNumber", "true");
		when(realm.getAuthenticatorConfigByAlias("sms-2fa")).thenReturn(config, (AuthenticatorConfigModel) null);
		submit("06 12 34 56 78");

		action.processAction(context);

		assertAccepted("0612345678");
	}

	@Test
	@DisplayName("A configuration emptied while formatting leaves the number as typed")
	void configurationEmptiedWhileFormattingKeepsTheNumber() {
		smsConfig.put("normalizePhoneNumber", "true");
		AuthenticatorConfigModel emptied = new AuthenticatorConfigModel();
		emptied.setConfig(null);
		when(realm.getAuthenticatorConfigByAlias("sms-2fa")).thenReturn(config, emptied);
		submit("06 12 34 56 78");

		action.processAction(context);

		assertAccepted("0612345678");
	}

	@Test
	@DisplayName("An empty number left unformatted, with no format error to show, goes on to validation")
	void emptyUnformattedNumberWithoutFormatErrorGoesOn() {
		smsConfig.put("normalizePhoneNumber", "true");
		smsConfig.put("forceRetryOnBadFormat", "true");
		when(realm.getAuthenticatorConfigByAlias("sms-2fa")).thenReturn(config, (AuthenticatorConfigModel) null);
		submit("");

		action.processAction(context);

		assertAccepted("");
	}

	@Test
	@DisplayName("With uniqueness and attribute storage on, a number used by another account is refused")
	void numberInUseIsRefused() {
		smsConfig.put("enforcePhoneNumberUniqueness", "true");
		smsConfig.put("storeInAttribute", "true");
		smsConfig.put("mobileNumberAttribute", "phone");
		UserModel other = mock(UserModel.class);
		when(users.searchForUserByUserAttributeStream(realm, "phone", FRENCH_MOBILE)).thenAnswer(call -> Stream.of(other));
		submit(FRENCH_MOBILE);

		action.processAction(context);

		assertRefusedWith("numberFormatNumberInUse");
		assertEquals("true", notes.get("numberFormatNumberInUse"));
	}

	@Test
	@DisplayName("With uniqueness and attribute storage on, an unused number is accepted")
	void unusedNumberIsAccepted() {
		smsConfig.put("enforcePhoneNumberUniqueness", "true");
		smsConfig.put("storeInAttribute", "true");
		when(users.searchForUserByUserAttributeStream(realm, "mobile_number", FRENCH_MOBILE))
			.thenAnswer(call -> Stream.empty());
		submit(FRENCH_MOBILE);

		action.processAction(context);

		assertAccepted(FRENCH_MOBILE);
	}

	@Test
	@DisplayName("Uniqueness is not checked without attribute storage")
	void uniquenessNeedsAttributeStorage() {
		smsConfig.put("enforcePhoneNumberUniqueness", "true");
		submit(FRENCH_MOBILE);

		action.processAction(context);

		assertAccepted(FRENCH_MOBILE);
		verify(users, never()).searchForUserByUserAttributeStream(any(), anyString(), anyString());
	}

	@Test
	@DisplayName("The form shows the placeholder and the country list")
	void challengeShowsThePlaceholderAndTheCountries() {
		notes.put("mobileInputFieldPlaceholder", "+33 6 ...");
		smsConfig.put("countryCodeList", "FR");

		action.requiredActionChallenge(context);

		verify(form).setAttribute("mobileInputFieldPlaceholder", "+33 6 ...");
		verify(form).setAttribute(eq("countryList"), argThat(list -> ((List<?>) list).size() == 1));
		verify(form).createForm("mobile_number_form.ftl");
		assertTrue(notes.containsKey("mobileInputFieldPlaceholder"));
	}
}
