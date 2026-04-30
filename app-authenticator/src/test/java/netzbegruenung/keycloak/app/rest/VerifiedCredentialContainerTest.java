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

package netzbegruenung.keycloak.app.rest;

import netzbegruenung.keycloak.app.credentials.AppCredentialModel;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.keycloak.credential.CredentialModel;
import org.keycloak.models.UserModel;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.Mockito.mock;

@DisplayName("VerifiedCredentialContainer")
class VerifiedCredentialContainerTest {

	@Nested
	@DisplayName("Creation")
	class Creation {

		@Test
		@DisplayName("should create record with all fields")
		void shouldCreateRecordWithAllFields() {
			UserModel user = mock(UserModel.class);
			CredentialModel credential = mock(CredentialModel.class);
			AppCredentialModel appCredential = mock(AppCredentialModel.class);

			VerifiedCredentialContainer container = new VerifiedCredentialContainer(user, credential, appCredential);

			assertEquals(user, container.user());
			assertEquals(credential, container.credential());
			assertEquals(appCredential, container.appCredential());
		}

		@Test
		@DisplayName("should handle null values")
		void shouldHandleNullValues() {
			VerifiedCredentialContainer container = new VerifiedCredentialContainer(null, null, null);

			assertNull(container.user());
			assertNull(container.credential());
			assertNull(container.appCredential());
		}
	}
}