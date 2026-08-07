package netzbegruenung.keycloak.app.actiontoken;

import netzbegruenung.keycloak.app.AppCredentialProviderFactory;
import netzbegruenung.keycloak.app.credentials.AppCredentialModel;
import netzbegruenung.keycloak.app.rest.AppCredentialService;
import netzbegruenung.keycloak.app.rest.StatusResourceProvider;
import org.keycloak.authentication.actiontoken.AbstractActionTokenHandler;
import org.keycloak.authentication.actiontoken.ActionTokenContext;
import org.keycloak.credential.CredentialProvider;
import org.keycloak.events.Errors;
import org.keycloak.events.EventType;
import org.keycloak.models.ModelDuplicateException;
import org.keycloak.models.UserModel;
import org.keycloak.services.messages.Messages;
import org.keycloak.sessions.AuthenticationSessionModel;

import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;

public class AppSetupActionTokenHandler extends AbstractActionTokenHandler<AppSetupActionToken> {
	public AppSetupActionTokenHandler() {
		super(
			AppSetupActionToken.TOKEN_TYPE,
			AppSetupActionToken.class,
			Messages.INVALID_REQUEST,
			EventType.EXECUTE_ACTION_TOKEN,
			Errors.INVALID_REQUEST
		);
	}

	@Override
	public Response handleToken(AppSetupActionToken token, ActionTokenContext<AppSetupActionToken> tokenContext) {
		MultivaluedMap<String, String> queryParameters = tokenContext.getRequest().getUri().getQueryParameters();
		String deviceId = queryParameters.getFirst("device_id");
		String deviceOs = queryParameters.getFirst("device_os");
		String publicKey = queryParameters.getFirst("public_key");
		String keyAlgorithm = queryParameters.getFirst("key_algorithm");
		String signatureAlgorithm = queryParameters.getFirst("signature_algorithm");
		String devicePushId = queryParameters.getFirst("device_push_id");

		if (
			deviceId == null
			|| deviceOs == null
			|| publicKey == null
			|| keyAlgorithm == null
			|| signatureAlgorithm == null
		) {
			return Response.status(400).build();
		}

		UserModel user = tokenContext.getAuthenticationSession().getAuthenticatedUser();
		AppCredentialService appCredentialService = new AppCredentialService(tokenContext.getSession());
		boolean deviceIdTaken = appCredentialService.isDeviceIdRegistered(tokenContext.getRealm(), deviceId);

		AuthenticationSessionModel authSession = ActionTokenUtil.getOriginalAuthSession(
			tokenContext.getSession(),
			tokenContext.getRealm(),
			token.getOriginalAuthenticationSessionId()
		);

		if (authSession == null) {
			return Response.status(Response.Status.FORBIDDEN).build();
		}

		if (deviceIdTaken) {
			authSession.setAuthNote("duplicateDeviceId", Boolean.toString(true));
			authSession.setAuthNote(StatusResourceProvider.READY, Boolean.toString(true));
			return Response.status(400).build();
		}

		CredentialProvider appCredentialProvider = tokenContext.getSession().getProvider(
			CredentialProvider.class,
			AppCredentialProviderFactory.PROVIDER_ID
		);
		try {
			appCredentialProvider.createCredential(
				tokenContext.getRealm(),
				user,
				AppCredentialModel.createAppCredential(publicKey, deviceId, deviceOs, keyAlgorithm, signatureAlgorithm, devicePushId)
			);
		} catch (ModelDuplicateException e) {
			// Lost a race against a concurrent registration of the same device_id.
			// AppCredentialProvider.createCredential already cleaned up the orphaned credential.
			authSession.setAuthNote("duplicateDeviceId", Boolean.toString(true));
			authSession.setAuthNote(StatusResourceProvider.READY, Boolean.toString(true));
			return Response.status(400).build();
		}

		authSession.setAuthNote("appSetupSuccessful", Boolean.toString(true));
		authSession.setAuthNote(StatusResourceProvider.READY, Boolean.toString(true));

		return Response.status(201).build();
	}

	@Override
	public boolean canUseTokenRepeatedly(AppSetupActionToken token, ActionTokenContext<AppSetupActionToken> tokenContext) {
		return false;
	}
}
