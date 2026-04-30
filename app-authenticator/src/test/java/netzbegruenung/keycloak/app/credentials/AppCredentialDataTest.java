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

import static org.assertj.core.api.Assertions.assertThat;

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

		assertThat(data.getPublicKey()).isEqualTo(publicKey);
		assertThat(data.getDeviceId()).isEqualTo(deviceId);
		assertThat(data.getDeviceOs()).isEqualTo(deviceOs);
		assertThat(data.getKeyAlgorithm()).isEqualTo(keyAlgorithm);
		assertThat(data.getSignatureAlgorithm()).isEqualTo(signatureAlgorithm);
		assertThat(data.getDevicePushId()).isEqualTo(devicePushId);
	}

	@Test
	@DisplayName("should allow updating device push ID")
	void shouldAllowUpdatingDevicePushId() {
		AppCredentialData data = new AppCredentialData("key", "device", "OS", "RSA", "SHA256withRSA", "push-1");

		data.setDevicePushId("push-2");

		assertThat(data.getDevicePushId()).isEqualTo("push-2");
	}

	@Test
	@DisplayName("should handle null values")
	void shouldHandleNullValues() {
		AppCredentialData data = new AppCredentialData(null, null, null, null, null, null);

		assertThat(data.getPublicKey()).isNull();
		assertThat(data.getDeviceId()).isNull();
		assertThat(data.getDeviceOs()).isNull();
	}
}
