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
import org.keycloak.authentication.RequiredActionProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

@DisplayName("PhoneValidationRequiredActionFactory")
@ExtendWith(MockitoExtension.class)
class PhoneValidationRequiredActionFactoryTest {

	private PhoneValidationRequiredActionFactory factory;
	@Mock
	private KeycloakSession session;

	@BeforeEach
	void setUp() {
		factory = new PhoneValidationRequiredActionFactory();
	}

	@Nested
	@DisplayName("Provider identification")
	class ProviderIdentification {

		@Test
		@DisplayName("should return correct provider ID")
		void shouldReturnCorrectProviderId() {
			assertThat(factory.getId()).isEqualTo("phone_validation_config");
		}

		@Test
		@DisplayName("should return correct display text")
		void shouldReturnCorrectDisplayText() {
			assertThat(factory.getDisplayText()).isEqualTo("Phone Validation");
		}
	}

	@Nested
	@DisplayName("Required action creation")
	class RequiredActionCreation {

		@Test
		@DisplayName("should create PhoneValidationRequiredAction instance")
		void shouldCreatePhoneValidationRequiredActionInstance() {
			RequiredActionProvider action = factory.create(session);

			assertThat(action).isInstanceOf(PhoneValidationRequiredAction.class);
		}

		@Test
		@DisplayName("should return singleton instance")
		void shouldReturnSingletonInstance() {
			RequiredActionProvider instance1 = factory.create(session);
			RequiredActionProvider instance2 = factory.create(session);

			assertThat(instance1).isSameAs(instance2);
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
