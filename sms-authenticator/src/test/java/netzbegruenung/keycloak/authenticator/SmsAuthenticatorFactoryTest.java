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

import static org.junit.jupiter.api.Assertions.*;
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

	@Test
	@DisplayName("should return correct provider ID")
	void shouldReturnCorrectProviderId() {
		assertEquals("mobile-number-authenticator", factory.getId());
		assertEquals("SMS Authentication (2FA)", factory.getDisplayType());
		assertEquals("Validates an OTP sent via SMS to the users mobile phone.", factory.getHelpText());
		assertEquals("mobile-number", factory.getReferenceCategory());
	}

	@Test
	@DisplayName("should create SmsAuthenticator instance")
	void shouldCreateSmsAuthenticatorInstance() {
		Authenticator authenticator = factory.create(session);

		assertInstanceOf(SmsAuthenticator.class, authenticator);
	}

	@Test
	@DisplayName("should return singleton instance")
	void shouldReturnSingletonInstance() {
		Authenticator instance1 = factory.create(session);
		Authenticator instance2 = factory.create(session);

		assertSame(instance1, instance2);
	}

	@Test
	@DisplayName("should be configurable")
	void shouldBeConfigurable() {
		assertTrue(factory.isConfigurable());
	}

	@Test
	@DisplayName("should allow user setup")
	void shouldAllowUserSetup() {
		assertTrue(factory.isUserSetupAllowed());
	}

	@Test
	@DisplayName("should return requirement choices")
	void shouldReturnRequirementChoices() {
		AuthenticationExecutionModel.Requirement[] requirements = factory.getRequirementChoices();

		assertTrue(List.of(requirements).contains(AuthenticationExecutionModel.Requirement.REQUIRED));
		assertTrue(List.of(requirements).contains(AuthenticationExecutionModel.Requirement.ALTERNATIVE));
		assertTrue(List.of(requirements).contains(AuthenticationExecutionModel.Requirement.DISABLED));
	}

	@Test
	@DisplayName("should return configuration properties")
	void shouldReturnConfigurationProperties() {
		List<ProviderConfigProperty> configProperties = factory.getConfigProperties();

		assertNotNull(configProperties);
		assertFalse(configProperties.isEmpty());
		assertTrue(configProperties.stream().anyMatch(p -> "length".equals(p.getName())));
		assertTrue(configProperties.stream().anyMatch(p -> "ttl".equals(p.getName())));
		assertTrue(configProperties.stream().anyMatch(p -> "senderId".equals(p.getName())));
		assertTrue(configProperties.stream().anyMatch(p -> "simulation".equals(p.getName())));
		assertTrue(configProperties.stream().anyMatch(p -> "countrycode".equals(p.getName())));
		assertTrue(configProperties.stream().anyMatch(p -> "apiurl".equals(p.getName())));
		assertTrue(configProperties.stream().anyMatch(p -> "forceSecondFactor".equals(p.getName())));
		assertTrue(configProperties.stream().anyMatch(p -> "normalizePhoneNumber".equals(p.getName())));
	}

	@Test
	@DisplayName("should have default code length of 6")
	void shouldHaveDefaultCodeLengthOf6() {
		List<ProviderConfigProperty> configProperties = factory.getConfigProperties();
		ProviderConfigProperty lengthProperty = configProperties.stream()
			.filter(p -> "length".equals(p.getName()))
			.findFirst()
			.orElseThrow();

		assertEquals(6, lengthProperty.getDefaultValue());
	}

	@Test
	@DisplayName("should have default TTL of 300 seconds")
	void shouldHaveDefaultTtlOf300Seconds() {
		List<ProviderConfigProperty> configProperties = factory.getConfigProperties();
		ProviderConfigProperty ttlProperty = configProperties.stream()
			.filter(p -> "ttl".equals(p.getName()))
			.findFirst()
			.orElseThrow();

		assertEquals("300", ttlProperty.getDefaultValue());
	}

	@Test
	@DisplayName("should have simulation mode enabled by default")
	void shouldHaveSimulationModeEnabledByDefault() {
		List<ProviderConfigProperty> configProperties = factory.getConfigProperties();
		ProviderConfigProperty simulationProperty = configProperties.stream()
			.filter(p -> "simulation".equals(p.getName()))
			.findFirst()
			.orElseThrow();

		assertTrue((Boolean) simulationProperty.getDefaultValue());
	}

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
