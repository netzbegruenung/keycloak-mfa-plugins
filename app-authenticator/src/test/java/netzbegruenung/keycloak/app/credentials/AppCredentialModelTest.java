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

package netzbegruenung.keycloak.app.credentials;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.keycloak.credential.CredentialModel;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("AppCredentialModel")
class AppCredentialModelTest {

	@Test
	@DisplayName("should have type APP_CREDENTIAL")
	void shouldHaveTypeAppCredential() {
		assertEquals("APP_CREDENTIAL", AppCredentialModel.TYPE);
	}

	@Test
	@DisplayName("should create credential with all fields")
	void shouldCreateCredentialWithAllFields() {
		String publicKey = "test-public-key";
		String deviceId = "device-123";
		String deviceOs = "Android";
		String keyAlgorithm = "RSA";
		String signatureAlgorithm = "SHA256withRSA";
		String devicePushId = "push-token-456";

		AppCredentialModel model = AppCredentialModel.createAppCredential(
			publicKey, deviceId, deviceOs, keyAlgorithm, signatureAlgorithm, devicePushId
		);

		assertNotNull(model);
		assertEquals("APP_CREDENTIAL", model.getType());
		assertEquals(publicKey, model.getAppCredentialData().getPublicKey());
		assertEquals(deviceId, model.getAppCredentialData().getDeviceId());
		assertEquals(deviceOs, model.getAppCredentialData().getDeviceOs());
		assertEquals(keyAlgorithm, model.getAppCredentialData().getKeyAlgorithm());
		assertEquals(signatureAlgorithm, model.getAppCredentialData().getSignatureAlgorithm());
		assertEquals(devicePushId, model.getAppCredentialData().getDevicePushId());
	}

	@Test
	@DisplayName("should set created date")
	void shouldSetCreatedDate() {
		long beforeCreation = System.currentTimeMillis();
		AppCredentialModel model = AppCredentialModel.createAppCredential(
			"key", "device", "OS", "RSA", "SHA256withRSA", "push"
		);
		long afterCreation = System.currentTimeMillis();

		assertTrue(model.getCreatedDate() >= beforeCreation);
		assertTrue(model.getCreatedDate() <= afterCreation + 1000);
	}

	@Test
	@DisplayName("should convert from CredentialModel")
	void shouldConvertFromCredentialModel() {
		String publicKey = "test-public-key";
		String deviceId = "device-123";
		String deviceOs = "Android";
		String keyAlgorithm = "RSA";
		String signatureAlgorithm = "SHA256withRSA";
		String devicePushId = "push-token-456";

		AppCredentialModel original = AppCredentialModel.createAppCredential(
			publicKey, deviceId, deviceOs, keyAlgorithm, signatureAlgorithm, devicePushId
		);

		CredentialModel credentialModel = new CredentialModel();
		credentialModel.setCredentialData(original.getCredentialData());
		credentialModel.setType("APP_CREDENTIAL");
		credentialModel.setId("test-id");
		credentialModel.setCreatedDate(1234567890L);
		credentialModel.setUserLabel("iOS");

		AppCredentialModel converted = AppCredentialModel.createFromCredentialModel(credentialModel);

		assertEquals("APP_CREDENTIAL", converted.getType());
		assertEquals("test-id", converted.getId());
		assertEquals(1234567890L, converted.getCreatedDate());
		assertEquals(deviceId, converted.getAppCredentialData().getDeviceId());
		/*
		  TODO fix it
		  assertEquals("iOS", converted.getUserLabel());
		 */
	}

	@Test
	@DisplayName("should update device push ID in credential data")
	void shouldUpdateDevicePushIdInCredentialData() {
		AppCredentialModel model = AppCredentialModel.createAppCredential(
			"key", "device", "OS", "RSA", "SHA256withRSA", "push-1"
		);

		model.updateDevicePushId("push-2");

		assertEquals("push-2", model.getAppCredentialData().getDevicePushId());

		String credentialData = model.getCredentialData();
		assertTrue(credentialData.contains("push-2"));
		assertFalse(credentialData.contains("push-1"));
	}
}
