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

package netzbegruenung.keycloak.authenticator.credentials;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("SmsAuthCredentialModel")
class SmsAuthCredentialModelTest {

	@Test
	@DisplayName("should create credential model with mobile number")
	void shouldCreateCredentialModelWithMobileNumber() {
		String mobileNumber = "+491761234567";
		SmsAuthCredentialModel credentialModel = SmsAuthCredentialModel.createSmsAuthenticator(mobileNumber);

		assertNotNull(credentialModel);
		assertEquals("mobile-number", credentialModel.getType());
		assertEquals(mobileNumber, credentialModel.getSmsAuthenticatorData().getMobileNumber());
	}

	@Test
	@DisplayName("should create credential model with E164 formatted mobile number")
	void shouldCreateCredentialModelWithE164FormattedMobileNumber() {
		String mobileNumber = "+491761234567";
		SmsAuthCredentialModel credentialModel = SmsAuthCredentialModel.createSmsAuthenticator(mobileNumber);

		assertTrue(credentialModel.getSmsAuthenticatorData().getMobileNumber().startsWith("+"));
	}

//    @Test
//    @DisplayName("should have credential data as JSON string")
//    void shouldHaveCredentialDataAsJsonString() {
//        String mobileNumber = "+491761234567";
//        SmsAuthCredentialModel credentialModel = SmsAuthCredentialModel.createSmsAuthenticator(mobileNumber);
//
//        String credentialData = credentialModel.getCredentialData();
//        assertThat(credentialData).isNotNull();
//        assertThat(credentialData).contains("mobile_number");
//        assertThat(credentialData).contains(mobileNumber);
//    }

	@Test
	@DisplayName("should create credential model from existing model")
	void shouldCreateCredentialModelFromExistingModel() {
		String mobileNumber = "+491761234567";
		SmsAuthCredentialModel originalModel = SmsAuthCredentialModel.createSmsAuthenticator(mobileNumber);

		// Create a mock CredentialModel for testing
		org.keycloak.credential.CredentialModel credentialModel = new org.keycloak.credential.CredentialModel();
		credentialModel.setCredentialData(originalModel.getCredentialData());
		credentialModel.setType("mobile-number");
		credentialModel.setId("test-id");
		credentialModel.setCreatedDate(1234567890L);

		SmsAuthCredentialModel recreatedModel = SmsAuthCredentialModel.createFromModel(credentialModel);

		assertNotNull(recreatedModel);
		assertEquals("mobile-number", recreatedModel.getType());
		assertEquals(mobileNumber, recreatedModel.getSmsAuthenticatorData().getMobileNumber());
	}

//    @Test
//    @DisplayName("should set user label with masked mobile number")
//    void shouldSetUserLabelWithMaskedMobileNumber() {
//        String mobileNumber = "+491761234567";
//        SmsAuthCredentialModel credentialModel = SmsAuthCredentialModel.createSmsAuthenticator(mobileNumber);
//
//        assertThat(credentialModel.getUserLabel()).contains("***");
//        assertThat(credentialModel.getUserLabel()).contains("567");
//    }
}
