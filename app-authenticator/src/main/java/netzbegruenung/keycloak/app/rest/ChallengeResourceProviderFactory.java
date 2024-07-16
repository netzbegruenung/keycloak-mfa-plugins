package netzbegruenung.keycloak.app.rest;

import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.services.resource.RealmResourceProviderFactory;

public class ChallengeResourceProviderFactory implements RealmResourceProviderFactory {

	public static final String ID = "challenges";

	@Override
	public RealmResourceProvider create(KeycloakSession session) {
		return new ChallengeResourceProvider(session);
	}

	@Override
	public void init(Config.Scope scope) {

	}

	@Override
	public void postInit(KeycloakSessionFactory keycloakSessionFactory) {
		ChallengeResourceProvider.scheduler.setRemoveOnCancelPolicy(true);
	}

	@Override
	public void close() {

	}

	@Override
	public String getId() {
		return ID;
	}
}
