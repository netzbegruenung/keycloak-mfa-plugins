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
import jakarta.ws.rs.core.Response;
import netzbegruenung.keycloak.authenticator.credentials.SmsAuthCredentialModel;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.authentication.RequiredActionContext;
import org.keycloak.credential.CredentialProvider;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.*;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.theme.Theme;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.IOException;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Properties;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@DisplayName("PhoneValidationRequiredAction")
@ExtendWith(MockitoExtension.class)
class PhoneValidationRequiredActionTest {

	private PhoneValidationRequiredAction action;

	@Mock
	private RequiredActionContext context;

	@Mock
	private UserModel user;

	@Mock
	private RealmModel realm;

	@Mock
	private KeycloakSession session;

	@Mock
	private AuthenticationSessionModel authSession;

	@Mock
	private LoginFormsProvider form;

	@Mock
	private AuthenticatorConfigModel authConfig;

	@Mock
	private KeycloakContext keycloakContext;

	@Mock
	private ThemeManager themeManager;

	@Mock
	private Theme theme;

	@Mock
	private Locale locale;

	@Mock
	private LoginFormsProvider loginFormsProvider;

	@Mock
	private Response challenge;

	@Mock
	private org.keycloak.http.HttpRequest httpRequest;

	@Mock
	private MultivaluedMap<String, String> formParameters;

	@Mock
	private SmsAuthCredentialProvider credentialProvider;

	@BeforeEach
	void setUp() {
		action = new PhoneValidationRequiredAction();
	}

	@Test
	@DisplayName("should have correct PROVIDER_ID")
	void shouldHaveCorrectProviderId() {
		assertEquals("phone_validation_config", PhoneValidationRequiredAction.PROVIDER_ID);
	}

	@Test
	@DisplayName("requiredActionChallenge should add PhoneNumberRequiredAction to user")
	void requiredActionChallengeShouldAddPhoneNumberRequiredAction() throws IOException {
		Map<String, String> configMap = new HashMap<>();
		configMap.put("length", "6");
		configMap.put("ttl", "300");

		Properties props = new Properties();
		props.setProperty("smsAuthText", "Your code is %s, valid for %d minutes");

		when(context.getUser()).thenReturn(user);
		when(context.getRealm()).thenReturn(realm);
		when(realm.getAuthenticatorConfigByAlias("sms-2fa")).thenReturn(authConfig);
		when(authConfig.getConfig()).thenReturn(configMap);
		when(context.getAuthenticationSession()).thenReturn(authSession);
		when(authSession.getAuthNote("mobile_number")).thenReturn("+491761234567");
		when(context.getSession()).thenReturn(session);
		when(session.getContext()).thenReturn(keycloakContext);
		when(session.theme()).thenReturn(themeManager);
		when(themeManager.getTheme(eq(Theme.Type.LOGIN))).thenReturn(theme);
		when(keycloakContext.resolveLocale(eq(user))).thenReturn(locale);
		when(theme.getEnhancedMessages(eq(realm), eq(locale))).thenReturn(props);
		when(context.form()).thenReturn(loginFormsProvider);
		when(loginFormsProvider.setAttribute(eq("realm"), eq(realm))).thenReturn(loginFormsProvider);
		when(loginFormsProvider.createForm(eq(SmsAuthenticator.TPL_CODE))).thenReturn(challenge);

		action.requiredActionChallenge(context);

		verify(context, times(1)).challenge(eq(challenge));
		verify(user).addRequiredAction(PhoneNumberRequiredAction.PROVIDER_ID);
		verify(authSession).setAuthNote(eq("code"), anyString());
		verify(authSession).setAuthNote(eq("ttl"), anyString());
	}

	@Test
	@DisplayName("processAction should succeed with valid code and create credential")
	void processActionShouldSucceedWithValidCode() throws IOException {
		Map<String, String> configMap = new HashMap<>();
		configMap.put("storeInAttribute", "true");

		String validCode = "123456";
		String mobileNumber = "+491761234567";
		long futureTtl = System.currentTimeMillis() + 300000L;

		when(context.getUser()).thenReturn(user);
		when(context.getHttpRequest()).thenReturn(httpRequest);
		when(httpRequest.getDecodedFormParameters()).thenReturn(formParameters);
		when(formParameters.getFirst("code")).thenReturn(validCode);
		when(context.getAuthenticationSession()).thenReturn(authSession);
		when(authSession.getAuthNote("mobile_number")).thenReturn(mobileNumber);
		when(authSession.getAuthNote("code")).thenReturn(validCode);
		when(authSession.getAuthNote("ttl")).thenReturn(String.valueOf(futureTtl));
		when(context.getSession()).thenReturn(session);
		when(session.getProvider(eq(CredentialProvider.class), eq("mobile-number"))).thenReturn(credentialProvider);
		when(context.getRealm()).thenReturn(realm);
		when(realm.getAuthenticatorConfigByAlias("sms-2fa")).thenReturn(authConfig);
		when(authConfig.getConfig()).thenReturn(configMap);

		action.processAction(context);

		verify(credentialProvider).createCredential(eq(realm), eq(user), any(SmsAuthCredentialModel.class));
		verify(user).removeRequiredAction(PhoneNumberRequiredAction.PROVIDER_ID);
		verify(user).setSingleAttribute(eq("mobile_number"), eq(mobileNumber));
		verify(context).success();
	}

	@Test
	@DisplayName("processAction should handle invalid code")
	void processActionShouldSucceedWithInvalidCode() throws IOException {
		String validCode = "123456";
		String invalidCode = "111111";
		String mobileNumber = "+491761234567";
		long futureTtl = System.currentTimeMillis() + 300000L;

		when(context.getHttpRequest()).thenReturn(httpRequest);
		when(httpRequest.getDecodedFormParameters()).thenReturn(formParameters);
		when(formParameters.getFirst("code")).thenReturn(invalidCode);
		when(context.getAuthenticationSession()).thenReturn(authSession);
		when(authSession.getAuthNote("mobile_number")).thenReturn(mobileNumber);
		when(authSession.getAuthNote("code")).thenReturn(validCode);
		when(authSession.getAuthNote("ttl")).thenReturn(String.valueOf(futureTtl));
		when(context.getRealm()).thenReturn(realm);
		when(context.form()).thenReturn(loginFormsProvider);
		when(loginFormsProvider.setAttribute(eq("realm"), eq(realm))).thenReturn(loginFormsProvider);
		when(loginFormsProvider.setError(eq("smsAuthCodeInvalid"))).thenReturn(loginFormsProvider);
		when(loginFormsProvider.createForm(eq(SmsAuthenticator.TPL_CODE))).thenReturn(challenge);


		action.processAction(context);

		verify(context).challenge(eq(challenge));
	}

	@Test
	@DisplayName("processAction should handle empty code")
	void processActionShouldHandleWithEmptyCode() throws IOException {
		String validCode = "123456";
		String mobileNumber = "+491761234567";
		long futureTtl = System.currentTimeMillis() + 300000L;

		when(context.getHttpRequest()).thenReturn(httpRequest);
		when(httpRequest.getDecodedFormParameters()).thenReturn(formParameters);
		when(context.getAuthenticationSession()).thenReturn(authSession);
		when(authSession.getAuthNote("mobile_number")).thenReturn(mobileNumber);
		when(authSession.getAuthNote("code")).thenReturn(validCode);
		when(authSession.getAuthNote("ttl")).thenReturn(String.valueOf(futureTtl));
		when(context.getRealm()).thenReturn(realm);
		when(context.form()).thenReturn(loginFormsProvider);
		when(loginFormsProvider.setAttribute(eq("realm"), eq(realm))).thenReturn(loginFormsProvider);
		when(loginFormsProvider.setError(eq("smsAuthCodeInvalid"))).thenReturn(loginFormsProvider);
		when(loginFormsProvider.createForm(eq(SmsAuthenticator.TPL_CODE))).thenReturn(challenge);

		action.processAction(context);

		verify(context).challenge(eq(challenge));
	}
}
