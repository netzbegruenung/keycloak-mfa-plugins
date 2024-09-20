package netzbegruenung.keycloak.enforce_mfa;

import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.authentication.*;
import org.keycloak.authentication.authenticators.conditional.ConditionalAuthenticator;
import org.keycloak.models.*;
import org.keycloak.models.utils.AuthenticationFlowResolver;
import org.keycloak.sessions.AuthenticationSessionModel;

import java.util.LinkedList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class EnforceMfaAuthenticator implements Authenticator {

	private static final Logger logger = Logger.getLogger(EnforceMfaAuthenticator.class);

	private static final String FORM_PARAM_MFA_METHOD = "mfaMethod";
	private static final String LOCALIZATION_PREFIX = "enforceMfa";

	public static final String CONFIG_OPTIONAL_NAME = "mfaSetupOptional";
	public static final Boolean CONFIG_OPTIONAL_DEFAULT_VALUE = false;

	@Override
	public void authenticate(AuthenticationFlowContext context) {
		List<RequiredActionProviderModel> requiredActions = getAllRequiredActions(context);

		if (requiredActions.isEmpty()) {
			logger.errorv(
				"No supported required actions enabled for user {0} in realm {1}",
				context.getAuthenticationSession().getAuthenticatedUser().getId(),
				context.getRealm().getName()
			);
			Response errorResponse = context.form()
				.setError("enforceMfaIllegalState")
				.createForm("enforce-mfa.ftl");
			context.failure(AuthenticationFlowError.INTERNAL_ERROR, errorResponse);
		} else {
			Response challenge = context.form()
				.setAttribute("mfa", requiredActions)
				.setAttribute("isSetupOptional", isSetupOptional(context.getAuthenticatorConfig()))
				.setAttribute("localizationPrefix", LOCALIZATION_PREFIX)
				.createForm("enforce-mfa.ftl");
			context.challenge(challenge);
		}
	}

	/**
	 * Get available required actions for 2FA setup
	 *
	 * @param context
	 * @return available required actions
	 */
	private List<RequiredActionProviderModel> getAllRequiredActions(AuthenticationFlowContext context) {
		List<RequiredActionProviderModel> alternativeRequiredActions = new LinkedList<>();

		getExecutions(context.getSession(), context.getRealm(), context.getExecution())
			.forEachOrdered(e -> {
				if (e.isAlternative()) {
					alternativeRequiredActions.addAll(getRequiredActions(context, e));
				}
			});
		return alternativeRequiredActions;
	}

	/**
	 * Collect executions of the current flow beneath base execution
	 * e.g. with base execution MFA-Authenticate-subflow will return OTP and WebAuthn
	 *
	 * - MFA-Authenticate-subflow CONDITIONAL
	 * -- Condition - user configured REQUIRED
	 * -- OTP ALTERNATIVE
	 * -- WebAuthn ALTERNATIVE
	 *
	 * @param session
	 * @param realm
	 * @param execution
	 * @return
	 */
	private Stream<AuthenticationExecutionModel> getExecutions(KeycloakSession session, RealmModel realm, AuthenticationExecutionModel execution) {
		AuthenticationExecutionModel baseExecution = getBaseExecution(realm, execution);

		return realm.getAuthenticationExecutionsStream(baseExecution.getFlowId())
			.filter(e -> !isConditionalExecution(session, e))
			.filter(e -> !Objects.equals(execution.getId(), e.getId()) && !e.isAuthenticatorFlow());
	}

	/**
	 * Given that execution is set to Enforce-MFA, then this function will return MFA-Authenticate-subflow
	 *
	 * - MFA-Authenticate-subflow CONDITIONAL
	 * -- Condition - user configured REQUIRED
	 * -- OTP ALTERNATIVE
	 * -- WebAuthn ALTERNATIVE
	 *
	 * - Register-MFA-subflow CONDITIONAL
	 * -- Condition - user configured REQUIRED
	 * -- Enforce-MFA REQUIRED
	 *
	 * @param realm
	 * @param execution
	 * @return base execution
	 */
	private AuthenticationExecutionModel getBaseExecution(RealmModel realm, AuthenticationExecutionModel execution) {
		AuthenticationExecutionModel parentExecution = realm.getAuthenticationExecutionByFlowId(execution.getParentFlow());

		Optional<AuthenticationExecutionModel> baseExecution = realm.getAuthenticationExecutionsStream(parentExecution.getParentFlow())
			.filter(AuthenticationExecutionModel::isAuthenticatorFlow)
			.findFirst();

		if (baseExecution.isEmpty()) {
			throw new IllegalStateException("This authenticator is only valid in combination with 2FA subflow");
		}
		return baseExecution.get();
	}

	private boolean isConditionalExecution(KeycloakSession session, AuthenticationExecutionModel e) {
		AuthenticatorFactory factory = (AuthenticatorFactory) session.getKeycloakSessionFactory()
			.getProviderFactory(Authenticator.class, e.getAuthenticator());
		if (factory != null) {
			Authenticator auth = factory.create(session);
			return (auth instanceof ConditionalAuthenticator);
		}
		return false;
	}

	/**
	 * Get required action provider for execution in flow
	 *
	 * @param context
	 * @param e
	 * @return
	 */
	private List<RequiredActionProviderModel> getRequiredActions(AuthenticationFlowContext context, AuthenticationExecutionModel e) {
		AuthenticatorFactory factory = (AuthenticatorFactory) context.getSession().getKeycloakSessionFactory()
			.getProviderFactory(Authenticator.class, e.getAuthenticator());
		Authenticator authenticator = factory.create(context.getSession());
		return authenticator.getRequiredActions(context.getSession())
			.stream()
			.map(f -> context.getRealm().getRequiredActionProviderByAlias(f.getId()))
			.filter(Objects::nonNull)
			.collect(Collectors.toList());
	}

	@Override
	public void action(AuthenticationFlowContext context) {
		MultivaluedMap<String, String> decodedFormParameters = context.getHttpRequest().getDecodedFormParameters();
		if(isSetupOptional(context.getAuthenticatorConfig()) && (!decodedFormParameters.containsKey(FORM_PARAM_MFA_METHOD) || decodedFormParameters.getFirst(FORM_PARAM_MFA_METHOD).isBlank())) {
			context.success();
			return;
		}

		if (!decodedFormParameters.containsKey(FORM_PARAM_MFA_METHOD)) {
			context.challenge(
				context.form().createErrorPage(Response.Status.BAD_REQUEST));
			context.failure(AuthenticationFlowError.CREDENTIAL_SETUP_REQUIRED);
			return;
		}

		String action = decodedFormParameters.getFirst(FORM_PARAM_MFA_METHOD);

		Stream<String> requiredActions = getAllRequiredActions(context).stream()
			.map(RequiredActionProviderModel::getProviderId);
		if (requiredActions.noneMatch(it -> it.equals(action))) {
			context.challenge(
				context.form().createErrorPage(Response.Status.BAD_REQUEST));
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
				.map(c -> c.getOrDefault(CONFIG_OPTIONAL_NAME, String.valueOf(CONFIG_OPTIONAL_DEFAULT_VALUE)))
				.map(Boolean::parseBoolean)
				.orElse(CONFIG_OPTIONAL_DEFAULT_VALUE);
	}

	@Override
	public boolean requiresUser() {
		return true;
	}

	@Override
	public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
		AuthenticationFlowModel browserFlow = AuthenticationFlowResolver.resolveBrowserFlow(
			session.getContext().getAuthenticationSession()
		);

		List<AuthenticationExecutionModel> executions = realm
			.getAuthenticationExecutionsStream(browserFlow.getId())
			.collect(Collectors.toList());

		AuthenticationExecutionModel execution = null;

		for (int i = 0; i < executions.size(); i++) {
			execution = executions.get(i);
			if (execution.isAuthenticatorFlow()) {
				executions.addAll(realm
					.getAuthenticationExecutionsStream(execution.getFlowId())
					.toList());
			} else if (EnforceMfaAuthenticatorFactory.PROVIDER_ID.equals(execution.getAuthenticator())) {
				break;
			}
		}

		if (execution == null) {
			return false;
		}

		return getExecutions(session, realm, execution)
			.noneMatch(e -> isAuthenticatorConfiguredFor(session, realm, user, e));
	}

	private boolean isAuthenticatorConfiguredFor(KeycloakSession session, RealmModel realm, UserModel user, AuthenticationExecutionModel e) {
		AuthenticatorFactory factory = (AuthenticatorFactory) session.getKeycloakSessionFactory()
			.getProviderFactory(Authenticator.class, e.getAuthenticator());
		Authenticator authenticator = factory.create(session);
		return authenticator.configuredFor(session, realm, user);
	}

	@Override
	public void setRequiredActions(KeycloakSession keycloakSession, RealmModel realmModel, UserModel userModel) {

	}

	@Override
	public void close() {

	}
}
