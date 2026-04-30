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
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.credential.CredentialProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.theme.Theme;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

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
		assertEquals("login-sms.ftl", SmsAuthenticator.TPL_CODE);
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
	@DisplayName("getType should return mobile-number type")
	void getTypeShouldReturnMobileNumberType() {
		SmsAuthCredentialModel.TYPE.equals("mobile-number");
		assertEquals("mobile-number", SmsAuthCredentialModel.TYPE);
	}
}
