package netzbegruenung.keycloak.app;

import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.CredentialValidator;
import org.keycloak.common.util.SecretGenerator;
import org.keycloak.credential.CredentialProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.sessions.AuthenticationSessionModel;

import javax.ws.rs.core.Cookie;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;

public class AppAuthenticator implements Authenticator, CredentialValidator<AppCredentialProvider> {
	private final Logger logger = Logger.getLogger(AppAuthenticator.class);

	private static final int SIGNATURE_LENGTH = 512;

	@Override
	public void authenticate(AuthenticationFlowContext context) {
		if (hasCookie(context)) {
			context.success();
			return;
		}

		String secret = SecretGenerator.getInstance().randomString(SIGNATURE_LENGTH, SecretGenerator.ALPHANUM);

		AuthenticationSessionModel authSession = context.getAuthenticationSession();
		authSession.setAuthNote("secret", secret);



		Response challenge = context.form()
			.createForm("app-login.ftl");
		context.challenge(challenge);
	}

	protected boolean hasCookie(AuthenticationFlowContext context) {
		Cookie cookie = context.getHttpRequest().getHttpHeaders().getCookies().get("APP_SECRET");
		boolean result = cookie != null;
		if (result) {
			logger.debugf("Bypassing app authenticator because cookie is set");
		}
		return result;
	}

	@Override
	public void action(AuthenticationFlowContext context) {
		AuthenticationSessionModel authSession = context.getAuthenticationSession();
		String secret = authSession.getAuthNote("secret");

		if (secret == null) {
			context.failureChallenge(AuthenticationFlowError.INTERNAL_ERROR,
				context.form().createErrorPage(Response.Status.INTERNAL_SERVER_ERROR));
			return;
		}

		String submittedSecret = context.getHttpRequest().getDecodedFormParameters().getFirst("secret");
	}

	protected boolean validateSecret(AuthenticationFlowContext context) {
		MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
		String secret = formData.getFirst("secret");
		return true;
	}

	@Override
	public boolean requiresUser() {
		return false;
	}

	@Override
	public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
		return getCredentialProvider(session).isConfiguredFor(realm, user, getType(session));
	}

	@Override
	public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
		user.addRequiredAction(AppRequiredAction.PROVIDER_ID);
	}

	@Override
	public void close() {

	}

	@Override
	public AppCredentialProvider getCredentialProvider(KeycloakSession session) {
		return (AppCredentialProvider)session.getProvider(CredentialProvider.class, AppCredentialProviderFactory.PROVIDER_ID);
	}
}
