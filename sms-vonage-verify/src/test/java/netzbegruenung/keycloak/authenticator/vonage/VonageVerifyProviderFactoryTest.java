package netzbegruenung.keycloak.authenticator.vonage;

import org.junit.jupiter.api.Test;
import org.keycloak.provider.ProviderConfigProperty;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class VonageVerifyProviderFactoryTest {

	private static ProviderConfigProperty property(String name) {
		return new VonageVerifyProviderFactory().getConfigProperties().stream()
			.filter(p -> p.getName().equals(name))
			.findFirst()
			.orElseThrow();
	}

	/**
	 * Keycloak masks only properties marked secret when it returns an authenticator config through the admin API
	 * or a realm export, and keeps the stored value when the masked placeholder is sent back.
	 */
	@Test
	void apiSecretIsMaskedByKeycloak() {
		assertTrue(property(VonageVerifyProvider.CONFIG_API_SECRET).isSecret());
	}

	@Test
	void apiKeyIsNotASecret() {
		assertFalse(property(VonageVerifyProvider.CONFIG_API_KEY).isSecret());
	}
}
