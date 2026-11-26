package netzbegruenung.keycloak.authenticator.verification;

import org.keycloak.models.KeycloakSession;

import java.util.Map;

/**
 * Looks up the {@link SmsVerificationProvider} selected in the SMS authenticator config.
 */
public final class SmsVerification {

	public static final String CONFIG_PROVIDER = "provider";

	private SmsVerification() {
	}

	public static SmsVerificationProvider getProvider(KeycloakSession session, Map<String, String> config)
			throws SmsVerificationException {
		String providerId = config.get(CONFIG_PROVIDER);
		if (providerId == null || providerId.isBlank()) {
			providerId = GenericSmsVerificationProviderFactory.PROVIDER_ID;
		}
		SmsVerificationProvider provider = session.getProvider(SmsVerificationProvider.class, providerId);
		if (provider == null) {
			throw new SmsVerificationException("SMS verification provider '" + providerId + "' is not installed");
		}
		return provider;
	}
}
