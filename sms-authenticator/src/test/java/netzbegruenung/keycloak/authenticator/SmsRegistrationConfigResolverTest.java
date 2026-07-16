package netzbegruenung.keycloak.authenticator;

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RequiredActionProviderModel;

import java.util.HashMap;
import java.util.Map;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class SmsRegistrationConfigResolverTest {

	private static RealmModel stubRealm(
		Map<String, String> requiredActionConfig,
		Map<String, String> legacyAuthenticatorConfig
	) {
		RealmModel realm = mock(RealmModel.class);
		if (requiredActionConfig != null) {
			RequiredActionProviderModel ra = mock(RequiredActionProviderModel.class);
			when(ra.getProviderId()).thenReturn(PhoneNumberRequiredAction.PROVIDER_ID);
			when(ra.getConfig()).thenReturn(requiredActionConfig);
			when(realm.getRequiredActionProvidersStream()).thenAnswer(inv -> Stream.of(ra));
		} else {
			when(realm.getRequiredActionProvidersStream()).thenAnswer(inv -> Stream.empty());
		}
		if (legacyAuthenticatorConfig != null) {
			AuthenticatorConfigModel legacy = mock(AuthenticatorConfigModel.class);
			when(legacy.getConfig()).thenReturn(legacyAuthenticatorConfig);
			when(realm.getAuthenticatorConfigByAlias(SmsRegistrationConfigResolver.LEGACY_DEFAULT_ALIAS))
				.thenReturn(legacy);
		} else {
			when(realm.getAuthenticatorConfigByAlias(SmsRegistrationConfigResolver.LEGACY_DEFAULT_ALIAS))
				.thenReturn(null);
		}
		return realm;
	}

	@Nested
	class IsInlineSmsRegistration {

		@Test
		void lengthOrTtlAloneDoesNotEnableInline() {
			assertFalse(SmsRegistrationConfigResolver.isInlineSmsRegistration(Map.of("length", "8")));
			assertFalse(SmsRegistrationConfigResolver.isInlineSmsRegistration(Map.of("ttl", "600")));
		}

		@Test
		void apiUrlEnablesInline() {
			assertTrue(SmsRegistrationConfigResolver.isInlineSmsRegistration(
				Map.of("apiurl", "https://sms.example/send")));
		}

		@Test
		void simulationTrueEnablesInline() {
			assertTrue(SmsRegistrationConfigResolver.isInlineSmsRegistration(Map.of("simulation", "true")));
		}

		@Test
		void simulationFalseAloneDoesNotEnableInline() {
			assertFalse(SmsRegistrationConfigResolver.isInlineSmsRegistration(Map.of("simulation", "false")));
		}

		@Test
		void blankApiUrlDoesNotEnableInline() {
			assertFalse(SmsRegistrationConfigResolver.isInlineSmsRegistration(Map.of("apiurl", "   ")));
			assertFalse(SmsRegistrationConfigResolver.isInlineSmsRegistration(Map.of("apiurl", "")));
		}

	}

	@Nested
	class GetMergedRegistrationConfig {

		@Test
		void legacyAliasAlone() {
			RealmModel realm = stubRealm(null, Map.of(
				"apiurl", "https://legacy.example/send",
				"apitoken", "legacy-secret",
				"length", "6",
				"ttl", "300"
			));

			Map<String, String> merged = SmsRegistrationConfigResolver.getMergedRegistrationConfig(realm);

			assertEquals("https://legacy.example/send", merged.get("apiurl"));
			assertEquals("legacy-secret", merged.get("apitoken"));
			assertEquals("6", merged.get("length"));
			assertEquals("300", merged.get("ttl"));
		}

		@Test
		void legacyWithoutLengthOrTtlGetsDefaults() {
			RealmModel realm = stubRealm(null, Map.of(
				"apiurl", "https://legacy.example/send"
			));

			Map<String, String> merged = SmsRegistrationConfigResolver.getMergedRegistrationConfig(realm);

			assertEquals(SmsRegistrationConfigResolver.DEFAULT_LENGTH, merged.get("length"));
			assertEquals(SmsRegistrationConfigResolver.DEFAULT_TTL_SECONDS, merged.get("ttl"));
		}

		@Test
		void inlineCompleteIgnoresLegacy() {
			Map<String, String> ra = Map.of(
				"apiurl", "https://inline.example/send",
				"apitoken", "inline-secret",
				"length", "8",
				"ttl", "120",
				"simulation", "false"
			);
			Map<String, String> legacy = Map.of(
				"apiurl", "https://legacy.example/send",
				"length", "6"
			);
			RealmModel realm = stubRealm(ra, legacy);

			Map<String, String> merged = SmsRegistrationConfigResolver.getMergedRegistrationConfig(realm);

			assertEquals("https://inline.example/send", merged.get("apiurl"));
			assertEquals("inline-secret", merged.get("apitoken"));
			assertEquals("8", merged.get("length"));
			assertEquals("120", merged.get("ttl"));
		}

		@Test
		void inlineWithApiUrlOnlyFillsFactoryDefaults() {
			RealmModel realm = stubRealm(Map.of(
				"apiurl", "https://inline.example/send"
			), Map.of("apiurl", "https://legacy.example/send"));

			Map<String, String> merged = SmsRegistrationConfigResolver.getMergedRegistrationConfig(realm);

			assertEquals("https://inline.example/send", merged.get("apiurl"));
			assertEquals("6", merged.get("length"));
			assertEquals("300", merged.get("ttl"));
			assertEquals("true", merged.get("simulation"));
		}

		@Test
		void partialRequiredActionUsesLegacyNotInline() {
			RealmModel realm = stubRealm(Map.of("length", "8"), Map.of(
				"apiurl", "https://legacy.example/send",
				"length", "6",
				"ttl", "300"
			));

			Map<String, String> merged = SmsRegistrationConfigResolver.getMergedRegistrationConfig(realm);

			assertEquals("https://legacy.example/send", merged.get("apiurl"));
			assertEquals("6", merged.get("length"));
		}

		@Test
		void emptyWhenNoLegacyAndNoInline() {
			RealmModel realm = stubRealm(null, null);

			assertTrue(SmsRegistrationConfigResolver.getMergedRegistrationConfig(realm).isEmpty());
		}
	}

	@Nested
	class GetEffectiveSmsConfigForExecution {

		@Test
		void executionConfigOverridesMergedBase() {
			RealmModel realm = stubRealm(null, Map.of(
				"apiurl", "https://legacy.example/send",
				"length", "6",
				"ttl", "300"
			));

			AuthenticatorConfigModel execution = mock(AuthenticatorConfigModel.class);
			when(execution.getConfig()).thenReturn(Map.of("length", "4", "ttl", "120"));

			Map<String, String> eff = SmsRegistrationConfigResolver.getEffectiveSmsConfigForExecution(realm, execution);

			assertEquals("4", eff.get("length"));
			assertEquals("120", eff.get("ttl"));
			assertEquals("https://legacy.example/send", eff.get("apiurl"));
		}

		@Test
		void inlineBaseWithExecutionOverride() {
			RealmModel realm = stubRealm(Map.of(
				"apiurl", "https://inline.example/send",
				"length", "8",
				"ttl", "120"
			), Map.of("apiurl", "https://legacy.example/send", "length", "6"));

			AuthenticatorConfigModel execution = mock(AuthenticatorConfigModel.class);
			when(execution.getConfig()).thenReturn(Map.of("ttl", "60"));

			Map<String, String> eff = SmsRegistrationConfigResolver.getEffectiveSmsConfigForExecution(realm, execution);

			assertEquals("https://inline.example/send", eff.get("apiurl"));
			assertEquals("8", eff.get("length"));
			assertEquals("60", eff.get("ttl"));
		}

		@Test
		void nullExecutionMatchesMergedRegistration() {
			RealmModel realm = stubRealm(null, Map.of(
				"apiurl", "https://legacy.example/send",
				"length", "6",
				"ttl", "300"
			));

			Map<String, String> merged = SmsRegistrationConfigResolver.getMergedRegistrationConfig(realm);
			Map<String, String> eff = SmsRegistrationConfigResolver.getEffectiveSmsConfigForExecution(realm, null);

			assertEquals(merged, eff);
		}

		@Test
		void blankExecutionValueDoesNotOverwriteBase() {
			RealmModel realm = stubRealm(null, Map.of(
				"apiurl", "https://legacy.example/send",
				"mobileInputFieldPlaceholder", "legacy-placeholder",
				"length", "6",
				"ttl", "300"
			));

			Map<String, String> executionCfg = new HashMap<>();
			executionCfg.put("mobileInputFieldPlaceholder", "");
			executionCfg.put("length", "   ");
			AuthenticatorConfigModel execution = mock(AuthenticatorConfigModel.class);
			when(execution.getConfig()).thenReturn(executionCfg);

			Map<String, String> eff = SmsRegistrationConfigResolver.getEffectiveSmsConfigForExecution(realm, execution);

			assertEquals("legacy-placeholder", eff.get("mobileInputFieldPlaceholder"));
			assertEquals("6", eff.get("length"));
		}
	}

	@Nested
	class MaterializeInlineRegistrationConfig {

		@Test
		void omitsBlankWhitelist() {
			Map<String, String> materialized = SmsRegistrationConfigResolver.materializeInlineRegistrationConfig(
				Map.of("apiurl", "https://inline.example/send")
			);

			assertNull(materialized.get("whitelist"));
		}

		@Test
		void includesNonBlankWhitelist() {
			Map<String, String> materialized = SmsRegistrationConfigResolver.materializeInlineRegistrationConfig(
				Map.of(
					"apiurl", "https://inline.example/send",
					"whitelist", "sms-exempt-role"
				)
			);

			assertEquals("sms-exempt-role", materialized.get("whitelist"));
		}
	}
}
