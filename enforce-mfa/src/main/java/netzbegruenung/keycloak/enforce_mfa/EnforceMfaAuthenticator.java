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
				.setAttribute("mfa", getAllRequiredActions(context))
				.createForm("enforce-mfa.ftl");
			context.challenge(challenge);
		}
	}

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

	private Stream<AuthenticationExecutionModel> getExecutions(KeycloakSession session, RealmModel realm, AuthenticationExecutionModel execution) {
		AuthenticationExecutionModel parentExecution = realm.getAuthenticationExecutionByFlowId(execution.getParentFlow());

		Optional<AuthenticationExecutionModel> firstExecution = realm.getAuthenticationExecutionsStream(parentExecution.getParentFlow())
			.filter(e -> e.isAuthenticatorFlow())
			.findFirst();

		if (!firstExecution.isPresent()) {
			throw new IllegalStateException("This authenticator is only valid in combination with 2FA subflow");
		}

		return realm.getAuthenticationExecutionsStream(firstExecution.get().getFlowId())
			.filter(e -> !isConditionalExecution(session, e))
			.filter(e -> !Objects.equals(execution.getId(), e.getId()) && !e.isAuthenticatorFlow());
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
			} else {
				if (EnforceMfaAuthenticatorFactory.PROVIDER_ID.equals(execution.getAuthenticator())) {
					break;
				}
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
