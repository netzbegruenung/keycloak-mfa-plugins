package netzbegruenung.keycloak.authenticator.verification;

import org.keycloak.provider.Provider;
import org.keycloak.provider.ProviderFactory;
import org.keycloak.provider.Spi;

/**
 * SPI for the "send a code" and "verify a code" steps of the SMS authenticator.
 */
public class SmsVerificationSpi implements Spi {

	public static final String NAME = "sms-verification";

	@Override
	public boolean isInternal() {
		return false;
	}

	@Override
	public String getName() {
		return NAME;
	}

	@Override
	public Class<? extends Provider> getProviderClass() {
		return SmsVerificationProvider.class;
	}

	@Override
	@SuppressWarnings("rawtypes")
	public Class<? extends ProviderFactory> getProviderFactoryClass() {
		return SmsVerificationProviderFactory.class;
	}
}
