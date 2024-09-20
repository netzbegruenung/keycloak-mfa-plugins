package netzbegruenung.keycloak.app;

import org.keycloak.credential.CredentialProvider;
import org.keycloak.credential.CredentialProviderFactory;
import org.keycloak.models.KeycloakSession;

public class AppCredentialProviderFactory implements CredentialProviderFactory<AppCredentialProvider> {
	public static final String PROVIDER_ID = "app-credential";
	@Override
	public AppCredentialProvider create(KeycloakSession keycloakSession) {
		return new AppCredentialProvider(keycloakSession);
	}

	@Override
	public String getId() {
		return PROVIDER_ID;
	}
}
