package netzbegruenung.keycloak.app;

import org.keycloak.Config;
import org.keycloak.authentication.RequiredActionFactory;
import org.keycloak.authentication.RequiredActionProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

public class AppRequiredActionFactory implements RequiredActionFactory {

	private static final AppRequiredAction SINGLETON = new AppRequiredAction();

	@Override
	public String getDisplayText() {
		return "Update App Authenticator";
	}

	@Override
	public RequiredActionProvider create(KeycloakSession keycloakSession) {
		return SINGLETON;
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
		return AppRequiredAction.PROVIDER_ID;
	}
}
