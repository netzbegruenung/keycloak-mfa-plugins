package netzbegruenung.keycloak.app.rest;

import org.keycloak.models.KeycloakSession;
import org.keycloak.services.resource.RealmResourceProvider;

public class ChallengeResourceProvider implements RealmResourceProvider {

	private KeycloakSession session;

	public ChallengeResourceProvider(KeycloakSession session) {
		this.session = session;
	}

	@Override
	public Object getResource() {
		return new ChallengeResource(session);
	}

	@Override
	public void close() {

	}
}
