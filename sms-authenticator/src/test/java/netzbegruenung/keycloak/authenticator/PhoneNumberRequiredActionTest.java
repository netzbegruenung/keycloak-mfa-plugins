/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package netzbegruenung.keycloak.authenticator;

import jakarta.ws.rs.core.MultivaluedMap;
import netzbegruenung.keycloak.authenticator.credentials.SmsAuthCredentialModel;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.authentication.InitiatedActionSupport;
import org.keycloak.authentication.RequiredActionContext;
import org.keycloak.credential.CredentialModel;
import org.keycloak.http.HttpRequest;
import org.keycloak.models.*;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@DisplayName("PhoneNumberRequiredAction")
@ExtendWith(MockitoExtension.class)
class PhoneNumberRequiredActionTest {

	private PhoneNumberRequiredAction action;

	@Mock
	private RequiredActionContext context;

	@Mock
	private RealmModel realm;

	@Mock
	private UserModel user;

	@Mock
	private KeycloakSession session;

	@Mock
	private KeycloakContext keycloakContext;

	@Mock
	private AuthenticationSessionModel authSession;

	@Mock
	private AuthenticatorConfigModel authConfig;

	@Mock
	private SubjectCredentialManager credentialManager;

	@Mock
	private RoleModel roleModel;

	@Mock
	private Stream<CredentialModel> credentials;

	@Mock
	private HttpRequest httpRequest;

	@Mock
	private MultivaluedMap<String, String> formParameters;

	@BeforeEach
	void setUp() {
		action = new PhoneNumberRequiredAction();
	}

	@Test
	@DisplayName("should have correct PROVIDER_ID")
	void shouldHaveCorrectProviderId() {
		assertEquals("mobile_number_config", PhoneNumberRequiredAction.PROVIDER_ID);
	}

	@Test
	@DisplayName("initiatedActionSupport should return SUPPORTED")
	void initiatedActionSupportShouldReturnSupported() {
		assertEquals(InitiatedActionSupport.SUPPORTED, action.initiatedActionSupport());
	}

	@Test
	@DisplayName("evaluateTriggers should skip when config not found")
	void evaluateTriggersShouldSkipWhenConfigNotFound() {
		Map<String, String> configMap = new HashMap<>();
		configMap.put("forceSecondFactor", "true");
		configMap.put("whitelist", "whitelist");

		when(context.getRealm()).thenReturn(realm);
		when(realm.getAuthenticatorConfigByAlias("sms-2fa")).thenReturn(authConfig);
		when(realm.getRole(eq("whitelist"))).thenReturn(roleModel);
		when(authConfig.getConfig()).thenReturn(configMap);
		when(context.getUser()).thenReturn(user);
		when(user.hasRole(roleModel)).thenReturn(false);
		when(context.getAuthenticationSession()).thenReturn(authSession);
		when(user.credentialManager()).thenReturn(credentialManager);
		when(credentialManager.getStoredCredentialsStream()).thenReturn(credentials);

		action.evaluateTriggers(context);

		verify(user, times(1)).addRequiredAction(eq(PhoneNumberRequiredAction.PROVIDER_ID));
	}

	@Test
	@DisplayName("getCountryCodeList should return empty list when countryCodeList is blank")
	void getCountryCodeListShouldReturnEmptyListWhenCountryCodeListBlank() {
		Map<String, String> configMap = new HashMap<>();
		configMap.put("countryCodeList", "");

		when(context.getRealm()).thenReturn(realm);
		when(context.getUser()).thenReturn(user);
		when(context.getSession()).thenReturn(session);
		when(realm.getAuthenticatorConfigByAlias("sms-2fa")).thenReturn(authConfig);
		when(authConfig.getConfig()).thenReturn(configMap);
		when(session.getContext()).thenReturn(keycloakContext);
		when(keycloakContext.resolveLocale(user)).thenReturn(java.util.Locale.ENGLISH);

		List<Map<String, String>> countryList = action.getCountryCodeList(context);

		assertTrue(countryList.isEmpty());
	}

	@Test
	@DisplayName("getCountryCodeList should return country list for valid country codes")
	void getCountryCodeListShouldReturnCountryListForValidCountryCodes() {
		Map<String, String> configMap = new HashMap<>();
		configMap.put("countryCodeList", "DE,US");

		when(context.getRealm()).thenReturn(realm);
		when(context.getUser()).thenReturn(user);
		when(context.getSession()).thenReturn(session);
		when(realm.getAuthenticatorConfigByAlias("sms-2fa")).thenReturn(authConfig);
		when(authConfig.getConfig()).thenReturn(configMap);
		when(session.getContext()).thenReturn(keycloakContext);
		when(keycloakContext.resolveLocale(user)).thenReturn(java.util.Locale.ENGLISH);

		List<Map<String, String>> countryList = action.getCountryCodeList(context);

		assertFalse(countryList.isEmpty());
		assertEquals(2, countryList.size());
	}

	@Test
	@DisplayName("close should not throw exception")
	void closeShouldNotThrowException() {
		action.close();
	}

	@Test
	@DisplayName("getCredentialType should return mobile-number type")
	void getCredentialTypeShouldReturnMobileNumberType() {
		String credentialType = action.getCredentialType(session, authSession);

		assertEquals(SmsAuthCredentialModel.TYPE, credentialType);
	}

	@Test
	@DisplayName("processAction should format phone number and add PhoneValidationRequiredAction")
	void processActionShouldFormatPhoneNumberAndAddValidationAction() {
		Map<String, String> configMap = new HashMap<>();
		configMap.put("countrycode", "49");
		configMap.put("normalizePhoneNumber", "true");
		configMap.put("forceRetryOnBadFormat", "false");

		String rawPhoneNumber = "01761234567";
		String formattedNumber = "+491761234567";

		when(context.getUser()).thenReturn(user);
		when(context.getHttpRequest()).thenReturn(httpRequest);
		when(httpRequest.getDecodedFormParameters()).thenReturn(formParameters);
		when(formParameters.getFirst("mobile_number")).thenReturn(rawPhoneNumber);
		when(formParameters.getFirst("country_code")).thenReturn("");
		when(context.getAuthenticationSession()).thenReturn(authSession);
		when(context.getRealm()).thenReturn(realm);
		when(realm.getAuthenticatorConfigByAlias("sms-2fa")).thenReturn(authConfig);
		when(authConfig.getConfig()).thenReturn(configMap);

		action.processAction(context);

		verify(authSession).setAuthNote(eq("mobile_number"), eq(formattedNumber));
		verify(authSession).addRequiredAction(eq(PhoneValidationRequiredAction.PROVIDER_ID));
		verify(context).success();
	}
}
