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

import netzbegruenung.keycloak.authenticator.credentials.SmsAuthCredentialModel;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.authentication.InitiatedActionSupport;
import org.keycloak.authentication.RequiredActionContext;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.*;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
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
	private LoginFormsProvider form;

	@Mock
	private AuthenticatorConfigModel authConfig;

	@Mock
	private RoleModel whitelistRole;

	@Mock
	private org.keycloak.models.SubjectCredentialManager credentialManager;

	@BeforeEach
	void setUp() {
		action = new PhoneNumberRequiredAction();
	}

	// Provider ID test
	@Test
	@DisplayName("should have correct PROVIDER_ID")
	void shouldHaveCorrectProviderId() {
		assertEquals("mobile_number_config", PhoneNumberRequiredAction.PROVIDER_ID);
	}

	// InitiatedActionSupport test
	@Test
	@DisplayName("initiatedActionSupport should return SUPPORTED")
	void initiatedActionSupportShouldReturnSupported() {
		assertEquals(InitiatedActionSupport.SUPPORTED, action.initiatedActionSupport());
	}

	// evaluateTriggers tests
	@Test
	@DisplayName("evaluateTriggers should skip when config not found")
	void evaluateTriggersShouldSkipWhenConfigNotFound() {
		when(context.getRealm()).thenReturn(realm);
		when(realm.getAuthenticatorConfigByAlias("sms-2fa")).thenReturn(null);

		action.evaluateTriggers(context);

		verify(user, never()).addRequiredAction((String) any());
	}

	@Test
	@DisplayName("evaluateTriggers should skip when forceSecondFactor is disabled")
	void evaluateTriggersShouldSkipWhenForceSecondFactorDisabled() {
		Map<String, String> configMap = new HashMap<>();
		configMap.put("forceSecondFactor", "false");

		when(context.getRealm()).thenReturn(realm);
		when(realm.getAuthenticatorConfigByAlias("sms-2fa")).thenReturn(authConfig);
		when(authConfig.getConfig()).thenReturn(configMap);

		action.evaluateTriggers(context);

		verify(user, never()).addRequiredAction((String) any());
	}

	@Test
	@DisplayName("evaluateTriggers should skip whitelisted user")
	void evaluateTriggersShouldSkipWhitelistedUser() {
		Map<String, String> configMap = new HashMap<>();
		configMap.put("forceSecondFactor", "true");
		configMap.put("whitelist", "whitelisted-role");

		when(context.getRealm()).thenReturn(realm);
		when(context.getUser()).thenReturn(user);
		when(realm.getAuthenticatorConfigByAlias("sms-2fa")).thenReturn(authConfig);
		when(authConfig.getConfig()).thenReturn(configMap);
		when(realm.getRole("whitelisted-role")).thenReturn(whitelistRole);
		when(user.hasRole(whitelistRole)).thenReturn(true);

		action.evaluateTriggers(context);

		verify(user, never()).addRequiredAction((String) any());
	}

	// getCountryCodeList tests
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

	// close test
	@Test
	@DisplayName("close should not throw exception")
	void closeShouldNotThrowException() {
		action.close();
	}

	// getCredentialType test
	@Test
	@DisplayName("getCredentialType should return mobile-number type")
	void getCredentialTypeShouldReturnMobileNumberType() {
		String credentialType = action.getCredentialType(session, authSession);

		assertEquals(SmsAuthCredentialModel.TYPE, credentialType);
	}
}
