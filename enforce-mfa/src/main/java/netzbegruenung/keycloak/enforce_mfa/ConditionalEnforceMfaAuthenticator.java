package netzbegruenung.keycloak.enforce_mfa;

import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.AuthenticationProcessor;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.Constants;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RequiredActionProviderModel;
import org.keycloak.models.UserModel;
import org.keycloak.sessions.AuthenticationSessionModel;

import java.util.LinkedList;
import java.util.List;
import java.util.Optional;

/**
 * MFA enrollment screen driven only by this execution's config (offered required actions).
 * {@link #configuredFor} uses {@link AuthenticationProcessor#CURRENT_AUTHENTICATION_EXECUTION} so the step works
 * without scanning sibling subflows (unlike {@link EnforceMfaAuthenticator}).
 */
public class ConditionalEnforceMfaAuthenticator implements Authenticator {

	private static final Logger LOG = Logger.getLogger(ConditionalEnforceMfaAuthenticator.class);

	public static final String FORM_PARAM_MFA_METHOD = "mfaMethod";
	/** Same i18n prefix as {@link EnforceMfaAuthenticator} ({@code enforce-mfa.ftl}). */
	private static final String LOCALIZATION_PREFIX = "enforceMfa";

	public static final Boolean CONFIG_OPTIONAL_DEFAULT_VALUE = false;

	@Override
	public void authenticate(AuthenticationFlowContext context) {
		AuthenticatorConfigModel authCfg = context.getAuthenticatorConfig();
		if (authCfg == null || authCfg.getConfig() == null) {
			LOG.error("conditional-enforce-mfa: missing authenticator config");
			failIllegal(context);
			return;
		}
		List<String> offeredIds = EnforceMfaShared.splitMultivalued(authCfg.getConfig(), EnforceMfaShared.CONFIG_OFFERED);
		if (offeredIds.isEmpty()) {
			LOG.error("conditional-enforce-mfa: offeredRequiredActions is empty");
			failIllegal(context);
			return;
		}

		List<RequiredActionProviderModel> models = resolveOffered(context.getRealm(), offeredIds);
		if (models.isEmpty()) {
			LOG.errorf(
				"No enabled required actions found for offered ids %s (realm=%s)",
				offeredIds,
				context.getRealm().getName()
			);
			failIllegal(context);
			return;
		}

		Response challenge = context.form()
			.setAttribute("mfa", models)
			.setAttribute("isSetupOptional", isSetupOptional(authCfg))
			.setAttribute("localizationPrefix", LOCALIZATION_PREFIX)
			.createForm("enforce-mfa.ftl");
		context.challenge(challenge);
	}

	private static void failIllegal(AuthenticationFlowContext context) {
		Response errorResponse = context.form()
			.setError("enforceMfaIllegalState")
			.setAttribute("localizationPrefix", LOCALIZATION_PREFIX)
			.createForm("enforce-mfa.ftl");
		context.failure(AuthenticationFlowError.INTERNAL_ERROR, errorResponse);
	}

	private static List<RequiredActionProviderModel> resolveOffered(RealmModel realm, List<String> ids) {
		List<RequiredActionProviderModel> out = new LinkedList<>();
		for (String id : ids) {
			findRequiredAction(realm, id).ifPresent(m -> {
				if (m.isEnabled()) {
					out.add(m);
				}
			});
		}
		return out;
	}

	private static Optional<RequiredActionProviderModel> findRequiredAction(RealmModel realm, String id) {
		RequiredActionProviderModel m = realm.getRequiredActionProviderById(id);
		if (m != null) {
			return Optional.of(m);
		}
		m = realm.getRequiredActionProviderByAlias(id);
		return Optional.ofNullable(m);
	}

	@Override
	public void action(AuthenticationFlowContext context) {
		MultivaluedMap<String, String> decodedFormParameters = context.getHttpRequest().getDecodedFormParameters();
		AuthenticatorConfigModel authCfg = context.getAuthenticatorConfig();
		if (authCfg == null || authCfg.getConfig() == null) {
			LOG.error("conditional-enforce-mfa action: missing authenticator config");
			context.failure(AuthenticationFlowError.INTERNAL_ERROR, context.form().createErrorPage(Response.Status.BAD_REQUEST));
			return;
		}
		if (isSetupOptional(authCfg)
			&& (!decodedFormParameters.containsKey(FORM_PARAM_MFA_METHOD)
			|| decodedFormParameters.getFirst(FORM_PARAM_MFA_METHOD).isBlank())) {
			context.success();
			return;
		}

		if (!decodedFormParameters.containsKey(FORM_PARAM_MFA_METHOD)) {
			context.challenge(context.form().createErrorPage(Response.Status.BAD_REQUEST));
			context.failure(AuthenticationFlowError.CREDENTIAL_SETUP_REQUIRED);
			return;
		}

		String action = decodedFormParameters.getFirst(FORM_PARAM_MFA_METHOD);

		List<String> offeredIds = EnforceMfaShared.splitMultivalued(authCfg.getConfig(), EnforceMfaShared.CONFIG_OFFERED);
		if (offeredIds.stream().noneMatch(action::equals)) {
			context.challenge(context.form().createErrorPage(Response.Status.BAD_REQUEST));
			context.failure(AuthenticationFlowError.CREDENTIAL_SETUP_REQUIRED);
			return;
		}

		AuthenticationSessionModel authenticationSession = context.getAuthenticationSession();
		if (!authenticationSession.getRequiredActions().contains(action)) {
			authenticationSession.addRequiredAction(action);
		}
		context.success();
	}

	private boolean isSetupOptional(AuthenticatorConfigModel config) {
		return Optional.ofNullable(config)
			.map(AuthenticatorConfigModel::getConfig)
			.map(c -> c.getOrDefault(EnforceMfaShared.CONFIG_OPTIONAL_NAME, String.valueOf(CONFIG_OPTIONAL_DEFAULT_VALUE)))
			.map(Boolean::parseBoolean)
			.orElse(CONFIG_OPTIONAL_DEFAULT_VALUE);
	}

	@Override
	public boolean requiresUser() {
		return true;
	}

	@Override
	public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
		Optional<AuthenticatorConfigModel> cfg = resolveOwnAuthenticatorConfig(session, realm);
		if (cfg.isEmpty()) {
			LOG.debug("[conditional-enforce-mfa] no config from auth note; assume step still required");
			return true;
		}
		return needsEnrollment(session, realm, user, cfg.get());
	}

	/**
	 * Step still required until at least one offered required action is satisfied (credential / pending state).
	 */
	static boolean needsEnrollment(
		KeycloakSession session,
		RealmModel realm,
		UserModel user,
		AuthenticatorConfigModel authCfg
	) {
		if (authCfg == null || authCfg.getConfig() == null) {
			return true;
		}
		List<String> offeredIds = EnforceMfaShared.splitMultivalued(authCfg.getConfig(), EnforceMfaShared.CONFIG_OFFERED);
		if (offeredIds.isEmpty()) {
			return true;
		}
		boolean anyOfferedSatisfied = offeredIds.stream()
			.anyMatch(id -> RequiredActionEnrollment.isSatisfied(session, realm, user, id));
		return !anyOfferedSatisfied;
	}

	/**
	 * Resolves the {@link AuthenticatorConfigModel} for the execution currently being evaluated, without walking flows.
	 */
	static Optional<AuthenticatorConfigModel> resolveOwnAuthenticatorConfig(KeycloakSession session, RealmModel realm) {
		var ctx = session.getContext();
		if (ctx == null) {
			return Optional.empty();
		}
		var authSession = ctx.getAuthenticationSession();
		if (authSession == null) {
			return Optional.empty();
		}
		String execId = authSession.getAuthNote(AuthenticationProcessor.CURRENT_AUTHENTICATION_EXECUTION);
		if (execId == null || execId.isBlank()) {
			execId = authSession.getAuthNote(Constants.AUTHENTICATION_EXECUTION);
		}
		if (execId == null || execId.isBlank()) {
			return Optional.empty();
		}
		AuthenticationExecutionModel execution = realm.getAuthenticationExecutionById(execId);
		if (execution == null || !ConditionalEnforceMfaAuthenticatorFactory.PROVIDER_ID.equals(execution.getAuthenticator())) {
			return Optional.empty();
		}
		String cfgId = execution.getAuthenticatorConfig();
		if (cfgId == null || cfgId.isBlank()) {
			return Optional.empty();
		}
		return Optional.ofNullable(realm.getAuthenticatorConfigById(cfgId));
	}

	@Override
	public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
	}

	@Override
	public void close() {
	}
}
