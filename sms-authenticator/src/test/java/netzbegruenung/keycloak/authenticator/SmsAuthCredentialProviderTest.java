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

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.credential.CredentialTypeMetadata;
import org.keycloak.credential.CredentialTypeMetadataContext;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

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

	@BeforeEach
	void setUp() {
		when(session.getContext()).thenReturn(keycloakContext);
		when(keycloakContext.getRealm()).thenReturn(realm);
		provider = new SmsAuthCredentialProvider(session);
	}

	// Credential type metadata tests
	@Test
	@DisplayName("should return correct credential type metadata")
	void shouldReturnCorrectCredentialTypeMetadata() {
		CredentialTypeMetadataContext context = mock(CredentialTypeMetadataContext.class);
		CredentialTypeMetadata metadata = provider.getCredentialTypeMetadata(context);

		assertEquals("mobile-number", metadata.getType());
		assertEquals(CredentialTypeMetadata.Category.TWO_FACTOR, metadata.getCategory());
	}

}
