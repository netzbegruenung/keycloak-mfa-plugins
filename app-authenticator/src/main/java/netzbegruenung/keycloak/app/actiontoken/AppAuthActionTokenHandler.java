package netzbegruenung.keycloak.app.actiontoken;

import org.keycloak.authentication.actiontoken.AbstractActionTokenHandler;
import org.keycloak.authentication.actiontoken.ActionTokenContext;
import org.keycloak.events.Errors;
import org.keycloak.events.EventType;
import org.keycloak.services.messages.Messages;
import org.keycloak.sessions.AuthenticationSessionModel;

import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;

public class AppAuthActionTokenHandler extends AbstractActionTokenHandler<AppAuthActionToken> {
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
		String secret = queryParameters.getFirst("secret");

		if (secret == null) {
			return Response.status(Response.Status.BAD_REQUEST).build();
		}

		AuthenticationSessionModel authSession = ActionTokenUtil.getOriginalAuthSession(
			tokenContext.getSession(),
			tokenContext.getRealm(),
			token.getOriginalCompoundAuthenticationSessionId()
		);
		if (!authSession.getAuthNote("secret").equals(secret)) {
			return Response.status(Response.Status.FORBIDDEN).build();
		}

		authSession.setAuthNote("appAuthSuccessful", Boolean.toString(true));
		return Response.status(Response.Status.NO_CONTENT).build();
	}

	@Override
	public boolean canUseTokenRepeatedly(AppAuthActionToken token, ActionTokenContext<AppAuthActionToken> tokenContext) {
		return false;
	}
}
