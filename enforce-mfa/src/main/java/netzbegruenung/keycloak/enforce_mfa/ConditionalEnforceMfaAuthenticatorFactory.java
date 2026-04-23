package netzbegruenung.keycloak.enforce_mfa;

import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;

import java.util.List;

public class ConditionalEnforceMfaAuthenticatorFactory implements AuthenticatorFactory {

	public static final String PROVIDER_ID = "conditional-enforce-mfa";

	private static final AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
		AuthenticationExecutionModel.Requirement.ALTERNATIVE,
		AuthenticationExecutionModel.Requirement.DISABLED,
		AuthenticationExecutionModel.Requirement.REQUIRED
	};

	@Override
	public String getDisplayType() {
		return "Conditional Enforce MFA (config lists)";
	}

	@Override
	public String getReferenceCategory() {
		return null;
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
		return false;
	}

	@Override
	public String getHelpText() {
		return "Offered = choices on screen. The step completes once at least one offered method is satisfied. "
			+ "Does not read sibling subflows; uses this execution's config only (current.authentication.execution note).";
	}

	@Override
	public List<ProviderConfigProperty> getConfigProperties() {
		return ProviderConfigurationBuilder.create()
			.property()
			.name(EnforceMfaShared.CONFIG_OFFERED)
			.label("Offered required actions")
			.helpText("Choices shown to the user. Must exist and be enabled in the realm.")
			.type(ProviderConfigProperty.MULTIVALUED_LIST_TYPE)
			.options(EnforceMfaShared.REQUIRED_ACTION_OPTIONS)
			.add()
			.property()
			.name(EnforceMfaShared.CONFIG_OPTIONAL_NAME)
			.label("MFA setup is optional")
			.helpText("Users can skip the setup screen.")
			.type(ProviderConfigProperty.BOOLEAN_TYPE)
			.defaultValue(ConditionalEnforceMfaAuthenticator.CONFIG_OPTIONAL_DEFAULT_VALUE)
			.add()
			.build();
	}

	@Override
	public Authenticator create(KeycloakSession session) {
		return new ConditionalEnforceMfaAuthenticator();
	}

	@Override
	public void init(Config.Scope config) {
	}

	@Override
	public void postInit(KeycloakSessionFactory factory) {
	}

	@Override
	public void close() {
	}

	@Override
	public String getId() {
		return PROVIDER_ID;
	}
}
