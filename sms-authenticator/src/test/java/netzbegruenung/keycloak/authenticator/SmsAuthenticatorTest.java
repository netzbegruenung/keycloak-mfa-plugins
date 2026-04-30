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
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.credential.CredentialModel;
import org.keycloak.credential.CredentialProvider;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.http.HttpRequest;
import org.keycloak.models.*;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.theme.Theme;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Locale;
import java.util.Map;
import java.util.Properties;
import java.util.stream.Stream;

import static netzbegruenung.keycloak.authenticator.SmsAuthenticator.TPL_CODE;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@DisplayName("SmsAuthenticator")
@ExtendWith(MockitoExtension.class)
class SmsAuthenticatorTest {

	private SmsAuthenticator authenticator;

	@Mock
	private AuthenticationFlowContext context;

	@Mock
	private UserModel user;

	@Mock
	private RealmModel realm;

	@Mock
	private KeycloakSession session;

	@Mock
	private SmsAuthCredentialProvider smsCredentialProvider;

	@Mock
	private Theme theme;

	@Mock
	private HttpRequest httpRequest;

	@Mock
	private MultivaluedMap<String, String> formParameters;

	@Mock
	private org.keycloak.models.SubjectCredentialManager credentialManager;

	@Mock
	private CredentialModel credentialModel;

	@Mock
	private AuthenticatorConfigModel authenticatorConfig;

	@Mock
	private AuthenticationSessionModel authSession;

	@Mock
	private ThemeManager themeManager;

	@Mock
	private KeycloakContext keycloakContext;

	@Mock
	private Locale locale;

	@Mock
	private Properties property;

	@Mock
	private LoginFormsProvider loginFormsProvider;

	@Mock
	private Response challenge;

	@BeforeEach
	void setUp() {
		authenticator = new SmsAuthenticator();
	}

	@Test
	@DisplayName("should implement Authenticator")
	void shouldImplementAuthenticator() {
		assertInstanceOf(Authenticator.class, authenticator);
	}

	@Test
	@DisplayName("should have correct TPL_CODE constant")
	void shouldHaveCorrectTplCodeConstant() {
		assertEquals("login-sms.ftl", TPL_CODE);
	}

	@Test
	@DisplayName("requiresUser should return true")
	void requiresUserShouldReturnTrue() {
		assertTrue(authenticator.requiresUser());
	}

	@Test
	@DisplayName("setRequiredActions should add PhoneNumberRequiredAction")
	void setRequiredActionsShouldAddPhoneNumberRequiredAction() {
		authenticator.setRequiredActions(session, realm, user);

		verify(user).addRequiredAction(PhoneNumberRequiredAction.PROVIDER_ID);
	}

	@Test
	@DisplayName("close should not throw exception")
	void closeShouldNotThrowException() {
		assertDoesNotThrow(authenticator::close);
	}

	@Test
	@DisplayName("getCredentialProvider should return SmsAuthCredentialProvider")
	void getCredentialProviderShouldReturnSmsAuthCredentialProvider() {
		when(session.getProvider(eq(CredentialProvider.class), eq(SmsAuthCredentialProviderFactory.PROVIDER_ID)))
			.thenReturn(smsCredentialProvider);

		SmsAuthCredentialProvider provider = authenticator.getCredentialProvider(session);

		assertNotNull(provider);
		assertSame(smsCredentialProvider, provider);
	}

	@Test
	@DisplayName("authenticate should validate SMS code and proceed on success")
	void authenticateShouldValidateSmsCodeAndProceedOnSuccess() throws java.io.IOException {
		String mobileNumber = "+491761234567";
		String credentialData = "{\"mobile_number\":\"" + mobileNumber + "\"}";

		when(user.credentialManager()).thenReturn(credentialManager);
		when(credentialManager.getStoredCredentialsByTypeStream(eq(SmsAuthCredentialModel.TYPE))).thenReturn(Stream.of(credentialModel));
		when(credentialModel.getCredentialData()).thenReturn(credentialData);
		when(context.getUser()).thenReturn(user);
		when(context.getRealm()).thenReturn(realm);
		when(context.getAuthenticatorConfig()).thenReturn(authenticatorConfig);
		when(authenticatorConfig.getConfig()).thenReturn(Map.of("length", "6", "ttl", "300"));
		when(context.getAuthenticationSession()).thenReturn(authSession);
		when(context.getSession()).thenReturn(session);
		when(session.theme()).thenReturn(themeManager);
		when(themeManager.getTheme(eq(Theme.Type.LOGIN))).thenReturn(theme);
		when(session.getContext()).thenReturn(keycloakContext);
		when(keycloakContext.resolveLocale(user)).thenReturn(locale);
		when(theme.getEnhancedMessages(eq(realm), eq(locale))).thenReturn(property);
		when(property.getProperty(eq("smsAuthText"))).thenReturn("");
		when(context.form()).thenReturn(loginFormsProvider);
		when(loginFormsProvider.setAttribute(eq("realm"), eq(realm))).thenReturn(loginFormsProvider);
		when(loginFormsProvider.createForm(TPL_CODE)).thenReturn(challenge);

		authenticator.authenticate(context);

		verify(context).challenge(eq(challenge));
	}

	@Test
	@DisplayName("action should proceed on valid SMS code")
	void actionShouldProceedOnValidSmsCode() {
		String enteredCode = "123456";
		String storedCode = "123456";
		String ttl = String.valueOf(System.currentTimeMillis() + 300000L);

		when(context.getHttpRequest()).thenReturn(httpRequest);
		when(httpRequest.getDecodedFormParameters()).thenReturn(formParameters);
		when(formParameters.getFirst("code")).thenReturn(enteredCode);
		when(context.getAuthenticationSession()).thenReturn(authSession);
		when(authSession.getAuthNote("code")).thenReturn(storedCode);
		when(authSession.getAuthNote("ttl")).thenReturn(ttl);

		authenticator.action(context);

		verify(context).success();
	}
}
