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

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("AppCredentialModel")
class AppCredentialModelTest {

	@Test
	@DisplayName("should have type APP_CREDENTIAL")
	void shouldHaveTypeAppCredential() {
		assertThat(AppCredentialModel.TYPE).isEqualTo("APP_CREDENTIAL");
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

		assertThat(model).isNotNull();
		assertThat(model.getType()).isEqualTo("APP_CREDENTIAL");
		assertThat(model.getAppCredentialData().getPublicKey()).isEqualTo(publicKey);
		assertThat(model.getAppCredentialData().getDeviceId()).isEqualTo(deviceId);
		assertThat(model.getAppCredentialData().getDeviceOs()).isEqualTo(deviceOs);
		assertThat(model.getAppCredentialData().getKeyAlgorithm()).isEqualTo(keyAlgorithm);
		assertThat(model.getAppCredentialData().getSignatureAlgorithm()).isEqualTo(signatureAlgorithm);
		assertThat(model.getAppCredentialData().getDevicePushId()).isEqualTo(devicePushId);
	}

	@Test
	@DisplayName("should set created date")
	void shouldSetCreatedDate() {
		long beforeCreation = System.currentTimeMillis();
		AppCredentialModel model = AppCredentialModel.createAppCredential(
			"key", "device", "OS", "RSA", "SHA256withRSA", "push"
		);
		long afterCreation = System.currentTimeMillis();

		assertThat(model.getCreatedDate()).isGreaterThanOrEqualTo(beforeCreation);
		assertThat(model.getCreatedDate()).isLessThanOrEqualTo(afterCreation + 1000);
	}

/*
    @Test
    @DisplayName("should set user label to device OS")
    void shouldSetUserLabelToDeviceOs() {
        AppCredentialModel model = AppCredentialModel.createAppCredential(
            "key", "device", "iOS", "RSA", "SHA256withRSA", "push"
        );

        assertThat(model.getUserLabel()).isEqualTo("iOS");
    }
*/

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

		assertThat(converted.getType()).isEqualTo("APP_CREDENTIAL");
		assertThat(converted.getId()).isEqualTo("test-id");
		assertThat(converted.getCreatedDate()).isEqualTo(1234567890L);
		assertThat(converted.getAppCredentialData().getDeviceId()).isEqualTo(deviceId);
		assertThat(converted.getUserLabel()).isEqualTo(deviceOs);
	}

	@Test
	@DisplayName("should update device push ID in credential data")
	void shouldUpdateDevicePushIdInCredentialData() {
		AppCredentialModel model = AppCredentialModel.createAppCredential(
			"key", "device", "OS", "RSA", "SHA256withRSA", "push-1"
		);

		model.updateDevicePushId("push-2");

		assertThat(model.getAppCredentialData().getDevicePushId()).isEqualTo("push-2");

		// Verify credential data was updated
		String credentialData = model.getCredentialData();
		assertThat(credentialData).contains("push-2");
		assertThat(credentialData).doesNotContain("push-1");
	}
}
