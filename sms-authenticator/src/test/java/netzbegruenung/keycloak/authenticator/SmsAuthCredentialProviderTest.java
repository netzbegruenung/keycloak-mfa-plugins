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

import netzbegruenung.keycloak.authenticator.credentials.SmsAuthCredentialData;
import netzbegruenung.keycloak.authenticator.credentials.SmsAuthCredentialModel;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.credential.CredentialInput;
import org.keycloak.credential.CredentialModel;
import org.keycloak.credential.CredentialTypeMetadata;
import org.keycloak.credential.CredentialTypeMetadataContext;
import org.keycloak.models.*;
import org.keycloak.util.JsonSerialization;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.IOException;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@DisplayName("SmsAuthCredentialProvider")
@ExtendWith(MockitoExtension.class)
class SmsAuthCredentialProviderTest {

	private SmsAuthCredentialProvider provider;

	@Mock
	private KeycloakSession session;

	@Mock
	private KeycloakContext keycloakContext;

	@Mock
	private RealmModel realm;

	@Mock
	private UserModel user;

	@Mock
	private org.keycloak.models.SubjectCredentialManager credentialManager;

	@Mock
	private CredentialModel credentialModel;

	@Mock
	private CredentialTypeMetadataContext context;

	@BeforeEach
	void setUp() {
		lenient().when(session.getContext()).thenReturn(keycloakContext);
		lenient().when(keycloakContext.getRealm()).thenReturn(realm);
		provider = new SmsAuthCredentialProvider(session);
	}

	@Test
	@DisplayName("should return correct credential type metadata")
	void shouldReturnCorrectCredentialTypeMetadata() {
		CredentialTypeMetadata metadata = provider.getCredentialTypeMetadata(context);

		assertEquals("mobile-number", metadata.getType());
		assertEquals(CredentialTypeMetadata.Category.TWO_FACTOR, metadata.getCategory());
	}

	@Test
	@DisplayName("isValid should return false for null challengeResponse")
	void isValidShouldReturnFalseForNullChallengeResponse() throws IOException {
		UserCredentialModel input = new UserCredentialModel("test-id", "mobile-number", "");

		when(user.credentialManager()).thenReturn(credentialManager);
		when(credentialManager.getStoredCredentialById(eq(input.getCredentialId()))).thenReturn(credentialModel);
		SmsAuthCredentialData smsAuthCredentialData = new SmsAuthCredentialData("+++");
		when(credentialModel.getCredentialData()).thenReturn(JsonSerialization.writeValueAsString(smsAuthCredentialData));

		boolean result = provider.isValid(realm, user, input);

		assertFalse(result);
	}

	@Test
	@DisplayName("updateCredential should update existing credential with new mobile number")
	void updateCredentialShouldUpdateExistingCredential() {
		String newMobileNumber = "+491769876543";
		String existingCredentialId = "existing-id";
		String credentialType = "mobile-number";

		CredentialInput input = new UserCredentialModel(existingCredentialId, credentialType, newMobileNumber);

		when(user.credentialManager()).thenReturn(credentialManager);
		when(credentialManager.getStoredCredentialsByTypeStream(eq(credentialType))).thenReturn(Stream.of(credentialModel));
		when(credentialModel.getId()).thenReturn(existingCredentialId);
		when(credentialManager.createStoredCredential(any(SmsAuthCredentialModel.class))).thenAnswer(invocation -> invocation.getArgument(0));

		boolean result = provider.updateCredential(realm, user, input);

		assertTrue(result);
		verify(credentialManager).removeStoredCredentialById(eq(existingCredentialId));
		verify(credentialManager).createStoredCredential(any(SmsAuthCredentialModel.class));
	}

	@Test
	@DisplayName("isConfiguredFor should return true when user has mobile-number credential")
	void isConfiguredForShouldReturnTrueWhenCredentialExists() {
		String credentialType = "mobile-number";

		when(user.credentialManager()).thenReturn(credentialManager);
		when(credentialManager.getStoredCredentialsByTypeStream(eq(credentialType))).thenReturn(Stream.of(credentialModel));

		boolean result = provider.isConfiguredFor(realm, user, credentialType);

		assertTrue(result);
	}
}
