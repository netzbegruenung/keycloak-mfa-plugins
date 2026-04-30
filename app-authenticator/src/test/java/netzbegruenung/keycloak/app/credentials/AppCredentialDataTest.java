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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

@DisplayName("AppCredentialData")
class AppCredentialDataTest {

	@Test
	@DisplayName("should store all credential data fields")
	void shouldStoreAllCredentialDataFields() {
		String publicKey = "test-public-key";
		String deviceId = "device-123";
		String deviceOs = "Android";
		String keyAlgorithm = "RSA";
		String signatureAlgorithm = "SHA256withRSA";
		String devicePushId = "push-token-456";

		AppCredentialData data = new AppCredentialData(publicKey, deviceId, deviceOs, keyAlgorithm, signatureAlgorithm, devicePushId);

		assertEquals(publicKey, data.getPublicKey());
		assertEquals(deviceId, data.getDeviceId());
		assertEquals(deviceOs, data.getDeviceOs());
		assertEquals(keyAlgorithm, data.getKeyAlgorithm());
		assertEquals(signatureAlgorithm, data.getSignatureAlgorithm());
		assertEquals(devicePushId, data.getDevicePushId());
	}

	@Test
	@DisplayName("should allow updating device push ID")
	void shouldAllowUpdatingDevicePushId() {
		AppCredentialData data = new AppCredentialData("key", "device", "OS", "RSA", "SHA256withRSA", "push-1");

		data.setDevicePushId("push-2");

		assertEquals("push-2", data.getDevicePushId());
	}

	@Test
	@DisplayName("should handle null values")
	void shouldHandleNullValues() {
		AppCredentialData data = new AppCredentialData(null, null, null, null, null, null);

		assertNull(data.getPublicKey());
		assertNull(data.getDeviceId());
		assertNull(data.getDeviceOs());
	}
}