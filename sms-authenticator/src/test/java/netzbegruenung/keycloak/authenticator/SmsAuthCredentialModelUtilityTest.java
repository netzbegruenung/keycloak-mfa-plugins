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
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.keycloak.common.util.Time;
import org.keycloak.credential.CredentialModel;
import org.keycloak.util.JsonSerialization;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("SmsAuthCredentialModel utility methods")
class SmsAuthCredentialModelUtilityTest {

	@Nested
	@DisplayName("Credential type")
	class CredentialType {

		@Test
		@DisplayName("should have type 'mobile-number'")
		void shouldHaveTypeMobileNumber() {
			assertEquals("mobile-number", SmsAuthCredentialModel.TYPE);
		}
	}

	@Nested
	@DisplayName("JSON serialization")
	class JsonSerializationTest {

		@Test
		@DisplayName("should serialize and deserialize credential data")
		void shouldSerializeAndDeserializeCredentialData() throws IOException {
			String mobileNumber = "+491761234567";
			SmsAuthCredentialData originalData = new SmsAuthCredentialData(mobileNumber);

			String json = JsonSerialization.writeValueAsString(originalData);
			SmsAuthCredentialData deserializedData = JsonSerialization.readValue(json, SmsAuthCredentialData.class);

			assertEquals(mobileNumber, deserializedData.getMobileNumber());
		}

		@Test
		@DisplayName("should handle empty mobile number in JSON")
		void shouldHandleEmptyMobileNumberInJson() throws IOException {
			String mobileNumber = "";
			SmsAuthCredentialData originalData = new SmsAuthCredentialData(mobileNumber);

			String json = JsonSerialization.writeValueAsString(originalData);
			SmsAuthCredentialData deserializedData = JsonSerialization.readValue(json, SmsAuthCredentialData.class);

			assertEquals("", deserializedData.getMobileNumber());
		}

		@Test
		@DisplayName("should handle null mobile number in JSON")
		void shouldHandleNullMobileNumberInJson() throws IOException {
			SmsAuthCredentialData originalData = new SmsAuthCredentialData(null);

			String json = JsonSerialization.writeValueAsString(originalData);
			SmsAuthCredentialData deserializedData = JsonSerialization.readValue(json, SmsAuthCredentialData.class);

			assertNull(deserializedData.getMobileNumber());
		}
	}

	@Nested
	@DisplayName("Credential model creation")
	class CredentialModelCreation {

		@Test
		@DisplayName("should set created date when creating credential")
		void shouldSetCreatedDateWhenCreatingCredential() {
			long beforeCreation = System.currentTimeMillis();
			SmsAuthCredentialModel credential = SmsAuthCredentialModel.createSmsAuthenticator("+491761234567");
			long afterCreation = System.currentTimeMillis();

			assertTrue(credential.getCreatedDate() >= beforeCreation);
			assertTrue(credential.getCreatedDate() <= afterCreation + 1000);
		}

		@Test
		@DisplayName("should fill credential model fields correctly")
		void shouldFillCredentialModelFieldsCorrectly() {
			String mobileNumber = "+491761234567";
			SmsAuthCredentialModel credential = SmsAuthCredentialModel.createSmsAuthenticator(mobileNumber);

			assertEquals("mobile-number", credential.getType());
			assertTrue(credential.getCredentialData().contains(mobileNumber));
		}
	}

	@Nested
	@DisplayName("User label generation")
	class UserLabelGeneration {

		@Test
		@DisplayName("should mask mobile number in user label for long numbers")
		void shouldMaskMobileNumberInUserLabelForLongNumbers() throws IOException {
			String mobileNumber = "+491761234567";
			CredentialModel model = new CredentialModel();
			model.setCredentialData(JsonSerialization.writeValueAsString(new SmsAuthCredentialData(mobileNumber)));
			model.setType("mobile-number");
			model.setId("test-id");
			model.setCreatedDate(Time.currentTimeMillis());

			SmsAuthCredentialModel credential = SmsAuthCredentialModel.createFromModel(model);

			assertTrue(credential.getUserLabel().contains("***"));
			assertTrue(credential.getUserLabel().endsWith("567"));
		}

		@Test
		@DisplayName("should show full number if short")
		void shouldShowFullNumberIfShort() throws IOException {
			String mobileNumber = "123";
			CredentialModel model = new CredentialModel();
			model.setCredentialData(JsonSerialization.writeValueAsString(new SmsAuthCredentialData(mobileNumber)));
			model.setType("mobile-number");
			model.setId("test-id");
			model.setCreatedDate(Time.currentTimeMillis());

			SmsAuthCredentialModel credential = SmsAuthCredentialModel.createFromModel(model);

			assertTrue(credential.getUserLabel().contains("123"));
		}
	}
}
