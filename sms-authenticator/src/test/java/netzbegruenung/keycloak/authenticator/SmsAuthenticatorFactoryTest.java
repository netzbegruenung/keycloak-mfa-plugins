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
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

@DisplayName("SmsAuthenticatorFactory")
@ExtendWith(MockitoExtension.class)
class SmsAuthenticatorFactoryTest {

	private SmsAuthenticatorFactory factory;
	@Mock
	private KeycloakSession session;

	@BeforeEach
	void setUp() {
		factory = new SmsAuthenticatorFactory();
	}

	@Nested
	@DisplayName("Provider identification")
	class ProviderIdentification {

		@Test
		@DisplayName("should return correct provider ID")
		void shouldReturnCorrectProviderId() {
			assertThat(factory.getId()).isEqualTo("mobile-number-authenticator");
		}

		@Test
		@DisplayName("should return correct display type")
		void shouldReturnCorrectDisplayType() {
			assertThat(factory.getDisplayType()).isEqualTo("SMS Authentication (2FA)");
		}

		@Test
		@DisplayName("should return correct help text")
		void shouldReturnCorrectHelpText() {
			assertThat(factory.getHelpText()).isEqualTo("Validates an OTP sent via SMS to the users mobile phone.");
		}

		@Test
		@DisplayName("should return correct reference category")
		void shouldReturnCorrectReferenceCategory() {
			assertThat(factory.getReferenceCategory()).isEqualTo("mobile-number");
		}
	}

	@Nested
	@DisplayName("Authenticator creation")
	class AuthenticatorCreation {

		@Test
		@DisplayName("should create SmsAuthenticator instance")
		void shouldCreateSmsAuthenticatorInstance() {
			Authenticator authenticator = factory.create(session);

			assertThat(authenticator).isInstanceOf(SmsAuthenticator.class);
		}

		@Test
		@DisplayName("should return singleton instance")
		void shouldReturnSingletonInstance() {
			Authenticator instance1 = factory.create(session);
			Authenticator instance2 = factory.create(session);

			assertThat(instance1).isSameAs(instance2);
		}
	}

	@Nested
	@DisplayName("Configuration")
	class Configuration {

		@Test
		@DisplayName("should be configurable")
		void shouldBeConfigurable() {
			assertThat(factory.isConfigurable()).isTrue();
		}

		@Test
		@DisplayName("should allow user setup")
		void shouldAllowUserSetup() {
			assertThat(factory.isUserSetupAllowed()).isTrue();
		}

		@Test
		@DisplayName("should return requirement choices")
		void shouldReturnRequirementChoices() {
			AuthenticationExecutionModel.Requirement[] requirements = factory.getRequirementChoices();

			assertThat(requirements).contains(
				AuthenticationExecutionModel.Requirement.REQUIRED,
				AuthenticationExecutionModel.Requirement.ALTERNATIVE,
				AuthenticationExecutionModel.Requirement.DISABLED
			);
		}

		@Test
		@DisplayName("should return configuration properties")
		void shouldReturnConfigurationProperties() {
			List<ProviderConfigProperty> configProperties = factory.getConfigProperties();

			assertThat(configProperties).isNotEmpty();
			assertThat(configProperties).extracting(ProviderConfigProperty::getName)
				.contains(
					"length",
					"ttl",
					"senderId",
					"simulation",
					"countrycode",
					"apiurl",
					"forceSecondFactor",
					"normalizePhoneNumber"
				);
		}

		@Test
		@DisplayName("should have default code length of 6")
		void shouldHaveDefaultCodeLengthOf6() {
			List<ProviderConfigProperty> configProperties = factory.getConfigProperties();
			ProviderConfigProperty lengthProperty = configProperties.stream()
				.filter(p -> "length".equals(p.getName()))
				.findFirst()
				.orElseThrow();

			assertThat(lengthProperty.getDefaultValue()).isEqualTo(6);
		}

		@Test
		@DisplayName("should have default TTL of 300 seconds")
		void shouldHaveDefaultTtlOf300Seconds() {
			List<ProviderConfigProperty> configProperties = factory.getConfigProperties();
			ProviderConfigProperty ttlProperty = configProperties.stream()
				.filter(p -> "ttl".equals(p.getName()))
				.findFirst()
				.orElseThrow();

			assertThat(ttlProperty.getDefaultValue()).isEqualTo("300");
		}

		@Test
		@DisplayName("should have simulation mode enabled by default")
		void shouldHaveSimulationModeEnabledByDefault() {
			List<ProviderConfigProperty> configProperties = factory.getConfigProperties();
			ProviderConfigProperty simulationProperty = configProperties.stream()
				.filter(p -> "simulation".equals(p.getName()))
				.findFirst()
				.orElseThrow();

			assertThat(simulationProperty.getDefaultValue()).isEqualTo(Boolean.TRUE);
		}
	}

	@Nested
	@DisplayName("Lifecycle")
	class Lifecycle {

		@Test
		@DisplayName("should not throw exception on init")
		void shouldNotThrowExceptionOnInit() {
			Config.Scope scope = mock(Config.Scope.class);
			factory.init(scope);
			// Should not throw
		}

		@Test
		@DisplayName("should not throw exception on postInit")
		void shouldNotThrowExceptionOnPostInit() {
			KeycloakSessionFactory sessionFactory = mock(KeycloakSessionFactory.class);
			factory.postInit(sessionFactory);
			// Should not throw
		}

		@Test
		@DisplayName("should not throw exception on close")
		void shouldNotThrowExceptionOnClose() {
			factory.close();
			// Should not throw
		}
	}
}
