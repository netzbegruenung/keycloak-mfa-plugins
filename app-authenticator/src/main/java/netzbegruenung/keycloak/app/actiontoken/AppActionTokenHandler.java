package netzbegruenung.keycloak.app.actiontoken;

import netzbegruenung.keycloak.app.AppCredentialProviderFactory;
import netzbegruenung.keycloak.app.credentials.AppCredentialModel;
import org.keycloak.authentication.actiontoken.AbstractActionTokenHandler;
import org.keycloak.authentication.actiontoken.ActionTokenContext;
import org.keycloak.credential.CredentialProvider;
import org.keycloak.events.Errors;
import org.keycloak.events.EventType;
import org.keycloak.models.ClientModel;
import org.keycloak.services.managers.AuthenticationSessionManager;
import org.keycloak.services.messages.Messages;
import org.keycloak.sessions.AuthenticationSessionCompoundId;
import org.keycloak.sessions.AuthenticationSessionModel;

import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;

public class AppActionTokenHandler extends AbstractActionTokenHandler<AppActionToken> {
	public AppActionTokenHandler() {
		super(
			AppActionToken.TOKEN_TYPE,
			AppActionToken.class,
			Messages.INVALID_REQUEST,
			EventType.EXECUTE_ACTION_TOKEN,
			Errors.INVALID_REQUEST
		);
	}

	@Override
	public Response handleToken(AppActionToken token, ActionTokenContext<AppActionToken> tokenContext) {
		MultivaluedMap<String, String> queryParameters = tokenContext.getRequest().getUri().getQueryParameters();
		String deviceId = queryParameters.getFirst("device_id");
		String deviceOs = queryParameters.getFirst("device_os");
		String publicKey = queryParameters.getFirst("public_key");

		if (
			deviceId == null
			|| deviceOs == null
			|| publicKey == null
		) {
			return Response.status(400).build();
		}

		CredentialProvider appCredentialProvider = tokenContext.getSession().getProvider(
			CredentialProvider.class,
			AppCredentialProviderFactory.PROVIDER_ID
		);
		appCredentialProvider.createCredential(
			tokenContext.getRealm(),
			tokenContext.getAuthenticationSession().getAuthenticatedUser(),
			AppCredentialModel.createAppCredential(publicKey, deviceId, deviceOs)
		);

		AuthenticationSessionManager asm = new AuthenticationSessionManager(tokenContext.getSession());
		AuthenticationSessionCompoundId compoundId = AuthenticationSessionCompoundId.encoded(token.getOriginalCompoundAuthenticationSessionId());
		ClientModel originalClient = tokenContext.getRealm().getClientById(compoundId.getClientUUID());
		AuthenticationSessionModel authSession = asm.getAuthenticationSessionByIdAndClient(
			tokenContext.getRealm(),
			compoundId.getRootSessionId(),
			originalClient,
			compoundId.getTabId()
		);
		authSession.setAuthNote("appSetupSuccessful", Boolean.toString(true));

		return Response.status(201).build();
	}

	@Override
	public boolean canUseTokenRepeatedly(AppActionToken token, ActionTokenContext<AppActionToken> tokenContext) {
		return false;
	}
}
