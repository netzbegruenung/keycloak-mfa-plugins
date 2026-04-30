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
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.Config;
import org.keycloak.authentication.RequiredActionProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;

@DisplayName("AppRequiredActionFactory")
@ExtendWith(MockitoExtension.class)
class AppRequiredActionFactoryTest {

	private AppRequiredActionFactory factory;
	@Mock
	private KeycloakSession session;

	@BeforeEach
	void setUp() {
		factory = new AppRequiredActionFactory();
	}

	// Provider identification tests
	@Test
	@DisplayName("should return correct provider ID")
	void shouldReturnCorrectProviderId() {
		assertEquals("app-register", factory.getId());
	}

	@Test
	@DisplayName("should return correct display text")
	void shouldReturnCorrectDisplayText() {
		assertEquals("Update App Authenticator", factory.getDisplayText());
	}

	// Required action creation tests
	@Test
	@DisplayName("should create AppRequiredAction instance")
	void shouldCreateAppRequiredActionInstance() {
		RequiredActionProvider action = factory.create(session);

		assertInstanceOf(AppRequiredAction.class, action);
	}

	@Test
	@DisplayName("should return singleton instance")
	void shouldReturnSingletonInstance() {
		RequiredActionProvider instance1 = factory.create(session);
		RequiredActionProvider instance2 = factory.create(session);

		assertSame(instance1, instance2);
	}

	// Lifecycle tests
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
