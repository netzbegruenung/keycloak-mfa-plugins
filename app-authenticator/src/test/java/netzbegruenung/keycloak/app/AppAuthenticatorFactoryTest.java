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

package netzbegruenung.keycloak.app;

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

@DisplayName("AppAuthenticatorFactory")
@ExtendWith(MockitoExtension.class)
class AppAuthenticatorFactoryTest {

	private AppAuthenticatorFactory factory;
	@Mock
	private KeycloakSession session;

	@BeforeEach
	void setUp() {
		factory = new AppAuthenticatorFactory();
	}

	@Nested
	@DisplayName("Provider identification")
	class ProviderIdentification {

		@Test
		@DisplayName("should return correct provider ID")
		void shouldReturnCorrectProviderId() {
			assertThat(factory.getId()).isEqualTo("app-authenticator");
		}

		@Test
		@DisplayName("should return correct display type")
		void shouldReturnCorrectDisplayType() {
			assertThat(factory.getDisplayType()).isEqualTo("App Authenticator");
		}

		@Test
		@DisplayName("should return correct reference category")
		void shouldReturnCorrectReferenceCategory() {
			assertThat(factory.getReferenceCategory()).isEqualTo("APP_CREDENTIAL");
		}

		@Test
		@DisplayName("should return correct help text")
		void shouldReturnCorrectHelpText() {
			assertThat(factory.getHelpText()).isEqualTo("Authenticator to grant access by mobile app.");
		}
	}

	@Nested
	@DisplayName("Authenticator creation")
	class AuthenticatorCreation {

		@Test
		@DisplayName("should create AppAuthenticator instance")
		void shouldCreateAppAuthenticatorInstance() {
			Authenticator authenticator = factory.create(session);

			assertThat(authenticator).isInstanceOf(AppAuthenticator.class);
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

			assertThat(configProperties).hasSize(2);
			assertThat(configProperties).extracting(ProviderConfigProperty::getName)
				.contains("simulation", "appAuthActionTokenExpiration");
		}

		@Test
		@DisplayName("should have simulation mode default to false")
		void shouldHaveSimulationModeDefaultToFalse() {
			List<ProviderConfigProperty> configProperties = factory.getConfigProperties();
			ProviderConfigProperty simulationProperty = configProperties.stream()
				.filter(p -> "simulation".equals(p.getName()))
				.findFirst()
				.orElseThrow();

			assertThat(simulationProperty.getDefaultValue()).isEqualTo(Boolean.FALSE);
		}

		@Test
		@DisplayName("should have default token expiration of 60 seconds")
		void shouldHaveDefaultTokenExpirationOf60Seconds() {
			List<ProviderConfigProperty> configProperties = factory.getConfigProperties();
			ProviderConfigProperty expirationProperty = configProperties.stream()
				.filter(p -> "appAuthActionTokenExpiration".equals(p.getName()))
				.findFirst()
				.orElseThrow();

			assertThat(expirationProperty.getDefaultValue()).isEqualTo(60);
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
		}

		@Test
		@DisplayName("should not throw exception on postInit")
		void shouldNotThrowExceptionOnPostInit() {
			KeycloakSessionFactory sessionFactory = mock(KeycloakSessionFactory.class);
			factory.postInit(sessionFactory);
		}

		@Test
		@DisplayName("should not throw exception on close")
		void shouldNotThrowExceptionOnClose() {
			factory.close();
		}
	}
}
