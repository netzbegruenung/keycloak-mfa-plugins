package netzbegruenung.keycloak.authenticator.vonage;

import netzbegruenung.keycloak.authenticator.verification.SmsVerificationProvider;
import netzbegruenung.keycloak.authenticator.verification.SmsVerificationProviderFactory;

import org.keycloak.models.KeycloakSession;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.List;

public class VonageVerifyProviderFactory implements SmsVerificationProviderFactory {

	public static final String PROVIDER_ID = "vonage-verify";
	private static final VonageVerifyProvider SINGLETON = new VonageVerifyProvider();

	@Override
	public String getId() {
		return PROVIDER_ID;
	}

	@Override
	public SmsVerificationProvider create(KeycloakSession session) {
		return SINGLETON;
	}

	@Override
	public List<ProviderConfigProperty> getConfigProperties() {
		return List.of(
			new ProviderConfigProperty(VonageVerifyProvider.CONFIG_API_KEY, "Vonage Verify: API key", "The API key of your Vonage account.", ProviderConfigProperty.STRING_TYPE, ""),
			new ProviderConfigProperty(VonageVerifyProvider.CONFIG_API_SECRET, "Vonage Verify: API secret", "The API secret of your Vonage account.", ProviderConfigProperty.PASSWORD, "", true),
			new ProviderConfigProperty(VonageVerifyProvider.CONFIG_BRAND, "Vonage Verify: Brand", "The name of your company or service, it is part of the SMS text. At most 18 characters, without the characters / { } : $ and backslash.", ProviderConfigProperty.STRING_TYPE, "Keycloak"),
			new ProviderConfigProperty(VonageVerifyProvider.CONFIG_LOCALE, "Vonage Verify: Locale (optional)", "A Vonage locale like en-us or de-de to use for all users. If empty, the locale of the user is used when Vonage supports it. Otherwise Vonage chooses the language from the country of the phone number.", ProviderConfigProperty.STRING_TYPE, ""),
			new ProviderConfigProperty(VonageVerifyProvider.CONFIG_TEMPLATE_ID, "Vonage Verify: Template ID (optional)", "The id of a custom template for the SMS text. If empty, the default text of Vonage is used.", ProviderConfigProperty.STRING_TYPE, ""),
			new ProviderConfigProperty(VonageVerifyProvider.CONFIG_BASE_URL, "Vonage Verify: API URL", "The base URL of the Vonage API.", ProviderConfigProperty.STRING_TYPE, VonageVerifyProvider.DEFAULT_BASE_URL)
		);
	}
}
