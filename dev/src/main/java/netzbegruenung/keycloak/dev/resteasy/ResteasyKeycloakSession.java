package netzbegruenung.keycloak.dev.resteasy;

import org.keycloak.models.KeycloakSession;
import org.keycloak.services.DefaultKeycloakContext;
import org.keycloak.services.DefaultKeycloakSession;
import org.keycloak.services.DefaultKeycloakSessionFactory;

public class ResteasyKeycloakSession extends DefaultKeycloakSession {
	public ResteasyKeycloakSession(DefaultKeycloakSessionFactory factory) {
		super(factory);
	}

	@Override
	protected DefaultKeycloakContext createKeycloakContext(KeycloakSession session) {
		return new ResteasyKeycloakContext(session);
	}
}
