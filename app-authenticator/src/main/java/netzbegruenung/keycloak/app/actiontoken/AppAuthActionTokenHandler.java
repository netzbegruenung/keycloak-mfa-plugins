package netzbegruenung.keycloak.app.actiontoken;

import netzbegruenung.keycloak.app.AppCredentialProvider;
import netzbegruenung.keycloak.app.AppCredentialProviderFactory;
import netzbegruenung.keycloak.app.AuthenticationUtil;
import netzbegruenung.keycloak.app.credentials.AppCredentialData;
import netzbegruenung.keycloak.app.credentials.AppCredentialModel;
import org.jboss.logging.Logger;
import org.keycloak.authentication.actiontoken.AbstractActionTokenHandler;
import org.keycloak.authentication.actiontoken.ActionTokenContext;
import org.keycloak.credential.CredentialModel;
import org.keycloak.credential.CredentialProvider;
import org.keycloak.events.Errors;
import org.keycloak.events.EventType;
import org.keycloak.services.messages.Messages;
import org.keycloak.sessions.AuthenticationSessionModel;

import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import java.util.HashMap;
import java.util.Map;

public class AppAuthActionTokenHandler extends AbstractActionTokenHandler<AppAuthActionToken> {

	private final Logger logger = Logger.getLogger(AppAuthActionTokenHandler.class);

	public AppAuthActionTokenHandler() {
		super(
			AppAuthActionToken.TOKEN_TYPE,
			AppAuthActionToken.class,
			Messages.INVALID_REQUEST,
			EventType.EXECUTE_ACTION_TOKEN,
			Errors.INVALID_REQUEST
		);
	}

	@Override
	public Response handleToken(AppAuthActionToken token, ActionTokenContext<AppAuthActionToken> tokenContext) {
		MultivaluedMap<String, String> queryParameters = tokenContext.getRequest().getUri().getQueryParameters();
		String granted = queryParameters.getFirst("granted");

		if (granted == null) {
			logger.warnf("App authentication rejected: missing query param \"granted\" for user ID [%s]", token.getUserId());
			return Response.status(Response.Status.BAD_REQUEST).build();
		}

		Map<String, String> signatureMap = AuthenticationUtil.getSignatureMap(tokenContext.getRequest().getHttpHeaders().getRequestHeader("Signature"));
		if (signatureMap == null) {
			logger.warnf("App authentication rejected: missing or incomplete signature header for user ID [%s]", token.getUserId());
			return Response.status(Response.Status.BAD_REQUEST).build();
		}

		AuthenticationSessionModel authSession = ActionTokenUtil.getOriginalAuthSession(
			tokenContext.getSession(),
			tokenContext.getRealm(),
			token.getOriginalAuthenticationSessionId()
		);

		if (authSession == null) {
			logger.warnf("App Authentication rejected: Auth session not found for user [%s]", token.getUserId());
			return Response.status(Response.Status.FORBIDDEN).build();
		}

		AppCredentialProvider appCredentialProvider = (AppCredentialProvider) tokenContext
			.getSession()
			.getProvider(CredentialProvider.class, AppCredentialProviderFactory.PROVIDER_ID);
		CredentialModel appCredentialModel = appCredentialProvider
			.getCredentialModel(authSession.getAuthenticatedUser(), authSession.getAuthNote("credentialId"));

		AppCredentialData appCredentialData = AppCredentialModel.createFromCredentialModel(appCredentialModel).getAppCredentialData();

		Map<String, String> signatureStringMap = new HashMap<>();
		signatureStringMap.put("created", authSession.getAuthNote("timestamp"));
		signatureStringMap.put("secret", authSession.getAuthNote("secret"));
		signatureStringMap.put("granted", granted);

		boolean verified = AuthenticationUtil.verifyChallenge(
			authSession.getAuthenticatedUser(),
			appCredentialData,
			AuthenticationUtil.getSignatureString(signatureStringMap).getBytes(),
			signatureMap.get("signature")
		);

		if (!verified) {
			return Response.status(Response.Status.FORBIDDEN).build();
		}

		if (!Boolean.parseBoolean(granted)) {
			authSession.setAuthNote("appAuthGranted", Boolean.toString(false));
		} else {
			authSession.setAuthNote("appAuthGranted", Boolean.toString(true));
		}

		return Response.status(Response.Status.NO_CONTENT).build();
	}

	@Override
	public boolean canUseTokenRepeatedly(AppAuthActionToken token, ActionTokenContext<AppAuthActionToken> tokenContext) {
		return false;
	}
}
