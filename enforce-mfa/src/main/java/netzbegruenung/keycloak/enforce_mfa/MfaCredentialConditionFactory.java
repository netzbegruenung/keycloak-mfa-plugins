package netzbegruenung.keycloak.enforce_mfa;

import org.keycloak.Config;
import org.keycloak.authentication.authenticators.conditional.ConditionalAuthenticator;
import org.keycloak.authentication.authenticators.conditional.ConditionalAuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;

import java.util.List;

public class MfaCredentialConditionFactory implements ConditionalAuthenticatorFactory {

	public static final String PROVIDER_ID = "mfa-credential-condition";

	public static final String CONFIG_CREDENTIAL_TYPES = "credentialTypes";
	public static final String CONFIG_COMBINE = "combine";
	public static final String CONFIG_INVERT_MATCH = "invertMatch";

	public static final String COMBINE_ALL = "ALL";
	public static final String COMBINE_ANY = "ANY";

	private static final AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
		AuthenticationExecutionModel.Requirement.REQUIRED,
		AuthenticationExecutionModel.Requirement.DISABLED,
	};

	@Override
	public ConditionalAuthenticator getSingleton() {
		return MfaCredentialCondition.INSTANCE;
	}

	@Override
	public String getDisplayType() {
		return "Condition - MFA credentials (enrolled)";
	}

	@Override
	public String getReferenceCategory() {
		return ConditionalAuthenticatorFactory.REFERENCE_CATEGORY;
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
		return "Matches when the user's registered credentials satisfy the policy. "
			+ "Select credential types (multiselect), then ALL (every type present) or ANY (at least one). "
			+ "Enable « Invert match » to branch when the policy is not satisfied (e.g. drive enrollment).";
	}

	@Override
	public List<ProviderConfigProperty> getConfigProperties() {
		return ProviderConfigurationBuilder.create()
			.property()
			.name(CONFIG_CREDENTIAL_TYPES)
			.label("Credential types")
			.helpText("Types already enrolled for the user (checked via Keycloak credential manager).")
			.type(ProviderConfigProperty.MULTIVALUED_LIST_TYPE)
			.options(EnforceMfaShared.CREDENTIAL_TYPE_OPTIONS)
			.add()
			.property()
			.name(CONFIG_COMBINE)
			.label("Combine types")
			.helpText("ALL: every selected type must be configured. ANY: at least one.")
			.type(ProviderConfigProperty.LIST_TYPE)
			.options(COMBINE_ALL, COMBINE_ANY)
			.defaultValue(COMBINE_ALL)
			.add()
			.property()
			.name(CONFIG_INVERT_MATCH)
			.label("Invert match")
			.helpText("If true, the outcome is reversed (true when the policy is not satisfied).")
			.type(ProviderConfigProperty.BOOLEAN_TYPE)
			.defaultValue(false)
			.add()
			.build();
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
