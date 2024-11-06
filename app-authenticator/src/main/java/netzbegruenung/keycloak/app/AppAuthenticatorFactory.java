package netzbegruenung.keycloak.app;

import netzbegruenung.keycloak.app.credentials.AppCredentialModel;
import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.Arrays;
import java.util.List;

public class AppAuthenticatorFactory implements AuthenticatorFactory {

	public static final String PROVIDER_ID = "app-authenticator";

	private static final AppAuthenticator SINGLETON = new AppAuthenticator();

	private static final AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
		AuthenticationExecutionModel.Requirement.REQUIRED,
		AuthenticationExecutionModel.Requirement.ALTERNATIVE,
		AuthenticationExecutionModel.Requirement.DISABLED
	};

	@Override
	public String getDisplayType() {
		return "App Authenticator";
	}

	@Override
	public String getReferenceCategory() {
		return AppCredentialModel.TYPE;
	}

	@Override
	public boolean isConfigurable() {
		return true;
	}

	@Override
	public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
		return REQUIREMENT_CHOICES;
	}

	@Override
	public boolean isUserSetupAllowed() {
		return true;
	}

	@Override
	public String getHelpText() {
		return "Authenticator to grant access by mobile app.";
	}

	@Override
	public List<ProviderConfigProperty> getConfigProperties() {
		ProviderConfigProperty simulationMode = new ProviderConfigProperty(
			"simulation",
			"Simulation Mode",
			"Logs app push notification instead of sending",
			ProviderConfigProperty.BOOLEAN_TYPE,
			false
		);
		ProviderConfigProperty appAuthActionTokenExpiration = new ProviderConfigProperty(
			"appAuthActionTokenExpiration",
			"App Auth Action Token expiration",
			"App Auth Action Token expiration time in seconds",
			ProviderConfigProperty.STRING_TYPE,
			60
		);
		return Arrays.asList(simulationMode, appAuthActionTokenExpiration);
	}

	@Override
	public Authenticator create(KeycloakSession keycloakSession) {
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
		return PROVIDER_ID;
	}
}
