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

import netzbegruenung.keycloak.authenticator.credentials.SmsAuthCredentialModel;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.credential.CredentialProvider;
import org.keycloak.models.KeycloakSession;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

@DisplayName("SmsAuthCredentialProviderFactory")
@ExtendWith(MockitoExtension.class)
class SmsAuthCredentialProviderFactoryTest {

	private SmsAuthCredentialProviderFactory factory;

	@BeforeEach
	void setUp() {
		factory = new SmsAuthCredentialProviderFactory();
	}

	@Nested
	@DisplayName("Provider identification")
	class ProviderIdentification {

		@Test
		@DisplayName("should return correct provider ID")
		void shouldReturnCorrectProviderId() {
			assertThat(factory.getId()).isEqualTo("mobile-number");
		}
	}

	@Nested
	@DisplayName("Credential provider creation")
	class CredentialProviderCreation {

		@Test
		@DisplayName("should create SmsAuthCredentialProvider instance")
		void shouldCreateSmsAuthCredentialProviderInstance() {
			KeycloakSession mockSession = mock(KeycloakSession.class);
			CredentialProvider<SmsAuthCredentialModel> provider = factory.create(mockSession);

			assertThat(provider).isInstanceOf(SmsAuthCredentialProvider.class);
		}
	}

	@Nested
	@DisplayName("Type compatibility")
	class TypeCompatibility {

		@Test
		@DisplayName("should support mobile-number credential type")
		void shouldSupportMobileNumberCredentialType() {
			KeycloakSession mockSession = mock(KeycloakSession.class);
			SmsAuthCredentialProvider provider = (SmsAuthCredentialProvider) factory.create(mockSession);

			assertThat(provider.supportsCredentialType("mobile-number")).isTrue();
		}

		@Test
		@DisplayName("should not support other credential types")
		void shouldNotSupportOtherCredentialTypes() {
			KeycloakSession mockSession = mock(KeycloakSession.class);
			SmsAuthCredentialProvider provider = (SmsAuthCredentialProvider) factory.create(mockSession);

			assertThat(provider.supportsCredentialType("other-type")).isFalse();
		}
	}

	@Nested
	@DisplayName("Lifecycle")
	class Lifecycle {

		@Test
		@DisplayName("should not throw exception on close")
		void shouldNotThrowExceptionOnClose() {
			factory.close();
			// Should not throw
		}
	}
}
