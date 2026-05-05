package netzbegruenung.keycloak.enforce_mfa;

import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.authenticators.conditional.ConditionalAuthenticator;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

import java.util.List;
import java.util.Locale;

/**
 * Condition that inspects credentials already registered for the current user and matches when a
 * policy (AND/OR list of credential types) is satisfied. Use {@code invertMatch} to branch the
 * opposite way (e.g. enrollment when credentials are missing).
 */
public final class MfaCredentialCondition implements ConditionalAuthenticator {

	static final MfaCredentialCondition INSTANCE = new MfaCredentialCondition();

	private static final Logger LOG = Logger.getLogger(MfaCredentialCondition.class);

	private MfaCredentialCondition() {
	}

	@Override
	public boolean matchCondition(AuthenticationFlowContext context) {
		UserModel user = context.getUser();
		if (user == null) {
			LOG.debug("mfa-credential-condition: no user in context");
			return applyInvert(false, context.getAuthenticatorConfig());
		}

		AuthenticatorConfigModel cfg = context.getAuthenticatorConfig();
		boolean satisfied = evaluatePolicy(user, cfg);
		return applyInvert(satisfied, cfg);
	}

	private static boolean applyInvert(boolean value, AuthenticatorConfigModel cfg) {
		if (cfg == null || cfg.getConfig() == null) {
			return value;
		}
		String inv = cfg.getConfig().get(MfaCredentialConditionFactory.CONFIG_INVERT_MATCH);
		if (Boolean.parseBoolean(inv)) {
			return !value;
		}
		return value;
	}

	static boolean evaluatePolicy(UserModel user, AuthenticatorConfigModel cfg) {
		if (cfg == null || cfg.getConfig() == null) {
			LOG.warn("mfa-credential-condition: missing config");
			return false;
		}
		var map = cfg.getConfig();
		List<String> types = EnforceMfaShared.splitMultivalued(map, MfaCredentialConditionFactory.CONFIG_CREDENTIAL_TYPES);
		if (types.isEmpty()) {
			LOG.warn("mfa-credential-condition: credentialTypes is empty");
			return false;
		}

		String combineRaw = map.getOrDefault(
			MfaCredentialConditionFactory.CONFIG_COMBINE,
			MfaCredentialConditionFactory.COMBINE_ALL
		).trim().toUpperCase(Locale.ROOT);

		boolean requireAll = switch (combineRaw) {
			case MfaCredentialConditionFactory.COMBINE_ALL -> true;
			case MfaCredentialConditionFactory.COMBINE_ANY -> false;
			default -> {
				LOG.warnv("mfa-credential-condition: unknown combine \"{0}\", defaulting to ALL", combineRaw);
				yield true;
			}
		};

		var credMgr = user.credentialManager();
		if (requireAll) {
			return types.stream().allMatch(credMgr::isConfiguredFor);
		}
		return types.stream().anyMatch(credMgr::isConfiguredFor);
	}

	@Override
	public void action(AuthenticationFlowContext context) {
	}

	@Override
	public boolean requiresUser() {
		return true;
	}

	@Override
	public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
	}

	@Override
	public void close() {
	}
}
