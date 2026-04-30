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

package netzbegruenung.keycloak.app.actiontoken;

import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.authentication.actiontoken.ActionTokenContext;
import org.keycloak.credential.CredentialProvider;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;

@DisplayName("AppSetupActionTokenHandler")
@ExtendWith(MockitoExtension.class)
class AppSetupActionTokenHandlerTest {

	private AppSetupActionTokenHandler handler;

	@Mock
	private ActionTokenContext<AppSetupActionToken> tokenContext;

	@Mock
	private AppSetupActionToken token;

	@Mock
	private KeycloakSession session;

	@Mock
	private RealmModel realm;

	@Mock
	private AuthenticationSessionModel authSession;

	@Mock
	private AuthenticationSessionModel originalAuthSession;

	@Mock
	private UserModel user;

	@Mock
	private CredentialProvider credentialProvider;

	@Mock
	private EventBuilder eventBuilder;

	@Mock
	private RealmResourceProvider statusResourceProvider;

	@Mock
	private org.keycloak.models.SubjectCredentialManager credentialManager;

	@Mock
	private ClientModel clientModel;

	@Mock
	private org.keycloak.models.KeycloakContext keycloakContext;

	@BeforeEach
	void setUp() {
		handler = new AppSetupActionTokenHandler();
	}

	private void setupTokenContextWithQueryParams(String... keyValues) {
		MultivaluedMap<String, String> queryParameters = new MultivaluedHashMap<>();
		for (int i = 0; i < keyValues.length; i += 2) {
			queryParameters.add(keyValues[i], keyValues[i + 1]);
		}

		org.keycloak.http.HttpRequest httpRequest = mock(org.keycloak.http.HttpRequest.class);
		jakarta.ws.rs.core.UriInfo uriInfo = mock(jakarta.ws.rs.core.UriInfo.class);
		lenient().when(uriInfo.getQueryParameters()).thenReturn(queryParameters);
		lenient().when(httpRequest.getUri()).thenReturn(uriInfo);
		lenient().when(httpRequest.getDecodedFormParameters()).thenReturn(new MultivaluedHashMap<>());
		lenient().when(tokenContext.getRequest()).thenReturn(httpRequest);
		lenient().when(tokenContext.getAuthenticationSession()).thenReturn(authSession);
		lenient().when(authSession.getAuthenticatedUser()).thenReturn(user);
		lenient().when(tokenContext.getSession()).thenReturn(session);
		lenient().when(session.getContext()).thenReturn(keycloakContext);
		lenient().when(keycloakContext.getRealm()).thenReturn(realm);
		lenient().when(user.credentialManager()).thenReturn(credentialManager);

		// Default stubbings for realm that are needed by the handler (lenient to allow null)
		lenient().when(realm.getClientById(any())).thenReturn(null);
	}

	private String buildQueryString(String[] keyValues) {
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < keyValues.length; i += 2) {
			if (i > 0) {
				sb.append("&");
			}
			sb.append(keyValues[i]).append("=").append(keyValues[i + 1]);
		}
		return sb.toString();
	}

	// Constructor tests
	@Test
	@DisplayName("should create handler with correct token type")
	void shouldCreateHandlerWithCorrectTokenType() {
		assertEquals("app-setup-action-token", AppSetupActionToken.TOKEN_TYPE);
	}

	// Token handling tests
	@Test
	@DisplayName("should return 400 when device_id is missing")
	void shouldReturn400WhenDeviceIdIsMissing() {
		setupTokenContextWithQueryParams("device_os", "Android", "public_key", "key", "key_algorithm", "RSA", "signature_algorithm", "SHA256withRSA");

		Response response = handler.handleToken(token, tokenContext);

		assertEquals(400, response.getStatus());
	}

	@Test
	@DisplayName("should return 400 when device_os is missing")
	void shouldReturn400WhenDeviceOsIsMissing() {
		setupTokenContextWithQueryParams("device_id", "device-123", "public_key", "key", "key_algorithm", "RSA", "signature_algorithm", "SHA256withRSA");

		Response response = handler.handleToken(token, tokenContext);

		assertEquals(400, response.getStatus());
	}

	@Test
	@DisplayName("should return 400 when public_key is missing")
	void shouldReturn400WhenPublicKeyIsMissing() {
		setupTokenContextWithQueryParams("device_id", "device-123", "device_os", "Android", "key_algorithm", "RSA", "signature_algorithm", "SHA256withRSA");

		Response response = handler.handleToken(token, tokenContext);

		assertEquals(400, response.getStatus());
	}

	@Test
	@DisplayName("should return 400 when key_algorithm is missing")
	void shouldReturn400WhenKeyAlgorithmIsMissing() {
		setupTokenContextWithQueryParams("device_id", "device-123", "device_os", "Android", "public_key", "key", "signature_algorithm", "SHA256withRSA");

		Response response = handler.handleToken(token, tokenContext);

		assertEquals(400, response.getStatus());
	}

	@Test
	@DisplayName("should return 400 when signature_algorithm is missing")
	void shouldReturn400WhenSignatureAlgorithmIsMissing() {
		setupTokenContextWithQueryParams("device_id", "device-123", "device_os", "Android", "public_key", "key", "key_algorithm", "RSA");

		Response response = handler.handleToken(token, tokenContext);

		assertEquals(400, response.getStatus());
	}

//	@Test
//	@DisplayName("should return 403 when original auth session is null")
//	void shouldReturn403WhenOriginalAuthSessionIsNull() {
//		setupTokenContextWithQueryParams("device_id", "device-123", "device_os", "Android", "public_key", "key", "key_algorithm", "RSA", "signature_algorithm", "SHA256withRSA");
//		when(token.getOriginalAuthenticationSessionId()).thenReturn("non-existent-session");
//		when(realm.getClientById(any())).thenReturn(null);
//
//		Response response = handler.handleToken(token, tokenContext);
//
//		assertEquals(403, response.getStatus());
//	}

//	@Test
//	@DisplayName("should return 400 when device ID already exists")
//	void shouldReturn400WhenDeviceIdAlreadyExists() {
//		String deviceId = "device-123";
//		setupTokenContextWithQueryParams("device_id", deviceId, "device_os", "Android", "public_key", "key", "key_algorithm", "RSA", "signature_algorithm", "SHA256withRSA");
//		when(token.getOriginalAuthenticationSessionId()).thenReturn("original-session");
//		when(realm.getClientById(any())).thenReturn(clientModel);
//
//		// Mock credential with valid JSON for AppCredentialData
//		CredentialModel mockCredentialModel = mock(CredentialModel.class);
//		AppCredentialModel mockAppCredential = mock(AppCredentialModel.class);
//		AppCredentialData mockData = new AppCredentialData("other-key", "other-device", "iOS", "RSA", "SHA256withRSA", "other-push");
//		when(mockAppCredential.getAppCredentialData()).thenReturn(mockData);
//		when(mockCredentialModel.getCredentialData()).thenReturn("{\"publicKey\":\"other-key\",\"deviceId\":\"other-device\",\"deviceOs\":\"iOS\",\"keyAlgorithm\":\"RSA\",\"signatureAlgorithm\":\"SHA256withRSA\",\"devicePushId\":\"other-push\"}");
//		when(credentialManager.getStoredCredentialsByTypeStream(AppCredentialModel.TYPE)).thenReturn(Stream.of(mockCredentialModel));
//
//		Response response = handler.handleToken(token, tokenContext);
//
//		assertEquals(400, response.getStatus());
//	}

//	@Test
//	@DisplayName("should create credential and return 201 when setup is successful")
//	void shouldCreateCredentialAndReturn201WhenSetupIsSuccessful() {
//		String deviceId = "device-123";
//		String deviceOs = "Android";
//		String publicKey = "test-public-key";
//		String keyAlgorithm = "RSA";
//		String signatureAlgorithm = "SHA256withRSA";
//		String devicePushId = "push-token-456";
//
//		setupTokenContextWithQueryParams("device_id", deviceId, "device_os", deviceOs, "public_key", publicKey, "key_algorithm", keyAlgorithm, "signature_algorithm", signatureAlgorithm, "device_push_id", devicePushId);
//		when(token.getOriginalAuthenticationSessionId()).thenReturn("original-session");
//		when(realm.getClientById(any())).thenReturn(clientModel);
//		when(tokenContext.getRealm()).thenReturn(realm);
//		when(session.getProvider(CredentialProvider.class, AppCredentialProviderFactory.PROVIDER_ID)).thenReturn(credentialProvider);
//
//		// Mock credential stream with different device ID (no conflict)
//		CredentialModel mockCredentialModel = mock(CredentialModel.class);
//		AppCredentialModel mockAppCredential = mock(AppCredentialModel.class);
//		AppCredentialData mockData = new AppCredentialData("other-key", "other-device", "iOS", "RSA", "SHA256withRSA", "other-push");
//		when(mockAppCredential.getAppCredentialData()).thenReturn(mockData);
//		when(mockCredentialModel.getCredentialData()).thenReturn("{\"publicKey\":\"other-key\",\"deviceId\":\"other-device\",\"deviceOs\":\"iOS\",\"keyAlgorithm\":\"RSA\",\"signatureAlgorithm\":\"SHA256withRSA\",\"devicePushId\":\"other-push\"}");
//		when(credentialManager.getStoredCredentialsByTypeStream(AppCredentialModel.TYPE)).thenReturn(Stream.of(mockCredentialModel));
//
//		Response response = handler.handleToken(token, tokenContext);
//
//		assertEquals(201, response.getStatus());
//		verify(credentialProvider).createCredential(eq(realm), eq(user), any(AppCredentialModel.class));
//	}

	// Token usage tests
	@Test
	@DisplayName("should not allow repeated token usage")
	void shouldNotAllowRepeatedTokenUsage() {
		boolean canReuse = handler.canUseTokenRepeatedly(token, tokenContext);

		assertTrue(!canReuse);
	}
}
