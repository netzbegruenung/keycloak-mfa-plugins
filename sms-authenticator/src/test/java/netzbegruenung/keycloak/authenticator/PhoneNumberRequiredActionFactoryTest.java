package netzbegruenung.keycloak.authenticator;

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.keycloak.component.ComponentValidationException;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RequiredActionConfigModel;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;

class PhoneNumberRequiredActionFactoryTest {

	private final PhoneNumberRequiredActionFactory factory = new PhoneNumberRequiredActionFactory();

	private static RequiredActionConfigModel config(Map<String, String> cfg) {
		RequiredActionConfigModel model = mock(RequiredActionConfigModel.class);
		org.mockito.Mockito.when(model.getConfig()).thenReturn(cfg);
		return model;
	}

	@Nested
	class ValidateConfig {

		@Test
		void inlineApiUrlOnlyAcceptsFactorySimulationDefault() {
			RequiredActionConfigModel model = config(Map.of("apiurl", "https://sms.example/send"));

			assertDoesNotThrow(() -> factory.validateConfig(mock(KeycloakSession.class), mock(RealmModel.class), model));
		}

		@Test
		void inlineSimulationTrueWithoutApiUrlAccepted() {
			RequiredActionConfigModel model = config(Map.of("simulation", "true"));

			assertDoesNotThrow(() -> factory.validateConfig(mock(KeycloakSession.class), mock(RealmModel.class), model));
		}

		@Test
		void simulationFalseAloneSkipsInlineValidation() {
			RequiredActionConfigModel model = config(Map.of("simulation", "false"));

			assertDoesNotThrow(() -> factory.validateConfig(mock(KeycloakSession.class), mock(RealmModel.class), model));
		}

		@Test
		void partialConfigSkipsValidation() {
			RequiredActionConfigModel model = config(Map.of("length", "8"));

			assertDoesNotThrow(() -> factory.validateConfig(mock(KeycloakSession.class), mock(RealmModel.class), model));
		}

		@Test
		void inlineWithNonIntegerLengthThrows() {
			RequiredActionConfigModel model = config(Map.of(
				"apiurl", "https://sms.example/send",
				"length", "abc"
			));

			assertThrows(
				ComponentValidationException.class,
				() -> factory.validateConfig(mock(KeycloakSession.class), mock(RealmModel.class), model)
			);
		}

		@Test
		void inlineWithSimulationFalseAndBlankApiUrlThrows() {
			RequiredActionConfigModel model = config(Map.of(
				"apiurl", "",
				"simulation", "false"
			));

			assertThrows(
				ComponentValidationException.class,
				() -> factory.validateConfig(mock(KeycloakSession.class), mock(RealmModel.class), model)
			);
		}

		@Test
		void inlineWithNonIntegerTtlThrows() {
			RequiredActionConfigModel model = config(Map.of(
				"apiurl", "https://sms.example/send",
				"ttl", "xyz"
			));

			assertThrows(
				ComponentValidationException.class,
				() -> factory.validateConfig(mock(KeycloakSession.class), mock(RealmModel.class), model)
			);
		}
	}
}
