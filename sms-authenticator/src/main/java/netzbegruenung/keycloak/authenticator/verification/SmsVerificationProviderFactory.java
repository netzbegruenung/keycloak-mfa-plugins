package netzbegruenung.keycloak.authenticator.verification;

import org.keycloak.Config;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderFactory;

import java.util.List;

public interface SmsVerificationProviderFactory extends ProviderFactory<SmsVerificationProvider> {

	/**
	 * Config properties this provider needs. They are added to the config of the SMS
	 * authenticator execution, and are available at runtime from
	 * {@link SmsVerificationContext#getConfig()}.
	 *
	 * All providers share one config map, so names must not collide with the properties of
	 * the SMS authenticator or of other providers. A prefix with the provider id is
	 * recommended.
	 */
	default List<ProviderConfigProperty> getConfigProperties() {
		return List.of();
	}

	@Override
	default void init(Config.Scope config) {
	}

	@Override
	default void postInit(KeycloakSessionFactory factory) {
	}

	@Override
	default void close() {
	}
}
