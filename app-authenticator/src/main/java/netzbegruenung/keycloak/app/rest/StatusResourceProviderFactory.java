package netzbegruenung.keycloak.app.rest;

import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.services.resource.RealmResourceProviderFactory;

public class StatusResourceProviderFactory implements RealmResourceProviderFactory {
	public static final String ID = "app-auth-status";

	@Override
	public RealmResourceProvider create(KeycloakSession session) {
		return new StatusResourceProvider(session);
	}

	@Override
	public void init(Config.Scope scope) {

	}

	@Override
	public void postInit(KeycloakSessionFactory keycloakSessionFactory) {

	}

	@Override
	public void close() {

	}

	@Override
	public String getId() {
		return ID;
	}
}
