package netzbegruenung.keycloak.enforce_mfa;

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

@DisplayName("EnforceMfaAuthenticatorFactory")
@ExtendWith(MockitoExtension.class)
class EnforceMfaAuthenticatorFactoryTest {

	private EnforceMfaAuthenticatorFactory factory;

	@Mock
	private KeycloakSession session;

	@Mock
	private KeycloakSessionFactory sessionFactory;

	@BeforeEach
	void setUp() {
		factory = new EnforceMfaAuthenticatorFactory();
	}

	@DisplayName("Provider ID should be enforce-mfa")
	@Test
	void shouldHaveCorrectProviderId() {
		assertEquals("enforce-mfa", factory.getId());
	}

	@DisplayName("Display type should be Enforce MFA")
	@Test
	void shouldHaveCorrectDisplayType() {
		assertEquals("Enforce MFA", factory.getDisplayType());
	}

	@DisplayName("Reference category should be null")
	@Test
	void shouldHaveNullReferenceCategory() {
		assertNull(factory.getReferenceCategory());
	}

	@DisplayName("Is configurable should return true")
	@Test
	void shouldBeConfigurable() {
		assertTrue(factory.isConfigurable());
	}

	@DisplayName("User setup allowed should return false")
	@Test
	void shouldNotAllowUserSetup() {
		assertFalse(factory.isUserSetupAllowed());
	}

	@DisplayName("Requirement choices should include ALTERNATIVE, DISABLED, REQUIRED")
	@Test
	void shouldHaveCorrectRequirementChoices() {
		AuthenticationExecutionModel.Requirement[] requirements = factory.getRequirementChoices();

		assertEquals(3, requirements.length);
		assertTrue(List.of(requirements).contains(AuthenticationExecutionModel.Requirement.ALTERNATIVE));
		assertTrue(List.of(requirements).contains(AuthenticationExecutionModel.Requirement.DISABLED));
		assertTrue(List.of(requirements).contains(AuthenticationExecutionModel.Requirement.REQUIRED));
	}

	@DisplayName("Config properties should include mfaSetupOptional")
	@Test
	void shouldHaveCorrectConfigProperties() {
		List<ProviderConfigProperty> configProperties = factory.getConfigProperties();

		assertFalse(configProperties.isEmpty());
		assertEquals(1, configProperties.size());
		assertEquals("mfaSetupOptional", configProperties.get(0).getName());
		assertEquals("MFA setup is optional", configProperties.get(0).getLabel());
//        assertEquals("BOOLEAN", configProperties.get(0).getType().name());
	}

	@DisplayName("Help text should mention conditional subflow")
	@Test
	void shouldHaveCorrectHelpText() {
		String helpText = factory.getHelpText();

		assertNotNull(helpText);
		assertTrue(helpText.contains("conditional"));
		assertTrue(helpText.contains("subflow"));
	}

	@DisplayName("Create should return EnforceMfaAuthenticator instance")
	@Test
	void shouldCreateEnforceMfaAuthenticator() {
		Authenticator authenticator = factory.create(session);

		assertNotNull(authenticator);
		assertInstanceOf(EnforceMfaAuthenticator.class, authenticator);
	}

//    @DisplayName("Create should return singleton instance")
//    @Test
//    void shouldReturnSingletonInstance() {
//        Authenticator instance1 = factory.create(session);
//        Authenticator instance2 = factory.create(session);
//
//        assertSame(instance1, instance2);
//    }

	@DisplayName("init should not throw exception")
	@Test
	void shouldNotThrowExceptionOnInit() {
		Config.Scope scope = mock(Config.Scope.class);

		assertDoesNotThrow(() -> factory.init(scope));
	}

	@DisplayName("postInit should not throw exception")
	@Test
	void shouldNotThrowExceptionOnPostInit() {
		assertDoesNotThrow(() -> factory.postInit(sessionFactory));
	}

	@DisplayName("close should not throw exception")
	@Test
	void shouldNotThrowExceptionOnClose() {
		assertDoesNotThrow(factory::close);
	}
}
