package netzbegruenung.keycloak.app;

import org.keycloak.authentication.CredentialRegistrator;
import org.keycloak.authentication.InitiatedActionSupport;
import org.keycloak.authentication.RequiredActionContext;
import org.keycloak.authentication.RequiredActionProvider;

public class AppRequiredAction implements RequiredActionProvider, CredentialRegistrator {

	public static String PROVIDER_ID = "app-register";

	@Override
	public InitiatedActionSupport initiatedActionSupport() {
		return InitiatedActionSupport.SUPPORTED;
	}

	@Override
	public void evaluateTriggers(RequiredActionContext requiredActionContext) {

	}

	@Override
	public void requiredActionChallenge(RequiredActionContext requiredActionContext) {

	}

	@Override
	public void processAction(RequiredActionContext requiredActionContext) {

	}

	@Override
	public void close() {

	}
}
