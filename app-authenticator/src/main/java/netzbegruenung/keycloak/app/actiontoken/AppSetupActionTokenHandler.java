package netzbegruenung.keycloak.app.actiontoken;

import netzbegruenung.keycloak.app.AppCredentialProviderFactory;
import netzbegruenung.keycloak.app.credentials.AppCredentialModel;
import netzbegruenung.keycloak.app.jpa.AppAuthCredentialIndex;
import netzbegruenung.keycloak.app.rest.AppCredentialService;
import netzbegruenung.keycloak.app.rest.StatusResourceProvider;
import org.keycloak.authentication.actiontoken.AbstractActionTokenHandler;
import org.keycloak.authentication.actiontoken.ActionTokenContext;
import org.keycloak.credential.CredentialProvider;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.models.ModelDuplicateException;
import org.keycloak.models.UserModel;
import org.keycloak.services.messages.Messages;
import org.keycloak.sessions.AuthenticationSessionModel;

import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;

public class AppSetupActionTokenHandler extends AbstractActionTokenHandler<AppSetupActionToken> {
	// Dedicated EXECUTE_ACTION_TOKEN_ERROR event errors, so failed app registrations are distinguishable
	// from Keycloak's own action tokens (verify email, reset password, ...)
	public static final String APP_SETUP_INVALID_REQUEST = "app_setup_invalid_request";
	public static final String APP_SETUP_SESSION_EXPIRED = "app_setup_session_expired";
	public static final String APP_SETUP_DUPLICATE_DEVICE_ID = "app_setup_duplicate_device_id";

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
			tokenContext.getEvent().user(token.getUserId()).error(APP_SETUP_INVALID_REQUEST);
			return Response.status(400).build();
		}

		UserModel user = tokenContext.getAuthenticationSession().getAuthenticatedUser();
		AppCredentialService appCredentialService = new AppCredentialService(tokenContext.getSession());
		AppAuthCredentialIndex existingIndex = appCredentialService.findByRealmAndDeviceId(tokenContext.getRealm(), deviceId);

		AuthenticationSessionModel authSession = ActionTokenUtil.getOriginalAuthSession(
			tokenContext.getSession(),
			tokenContext.getRealm(),
			token.getOriginalAuthenticationSessionId()
		);

		if (authSession == null) {
			tokenContext.getEvent().user(token.getUserId()).error(APP_SETUP_SESSION_EXPIRED);
			return Response.status(Response.Status.FORBIDDEN).build();
		}

		if (existingIndex != null && !existingIndex.getUser().getId().equals(user.getId())) {
			tokenContext.getEvent().user(user).detail("device_id", deviceId).error(APP_SETUP_DUPLICATE_DEVICE_ID);
			authSession.setAuthNote("duplicateDeviceId", Boolean.toString(true));
			authSession.setAuthNote(StatusResourceProvider.READY, Boolean.toString(true));
			return Response.status(400).build();
		}

		CredentialProvider appCredentialProvider = tokenContext.getSession().getProvider(
			CredentialProvider.class,
			AppCredentialProviderFactory.PROVIDER_ID
		);

		// Re-registering the same device_id the user already owns (e.g. reinstalling the app):
		// replace the old credential rather than rejecting. The old index row is removed by the
		// CREDENTIAL_ID -> CREDENTIAL onDelete=CASCADE FK (app-credential-index-changelog.xml), so
		// no separate index cleanup is needed here.
		boolean isOverwrite = existingIndex != null;
		if (isOverwrite) {
			appCredentialProvider.deleteCredential(tokenContext.getRealm(), user, existingIndex.getCredentialId());
		}

		try {
			appCredentialProvider.createCredential(
				tokenContext.getRealm(),
				user,
				AppCredentialModel.createAppCredential(publicKey, deviceId, deviceOs, keyAlgorithm, signatureAlgorithm, devicePushId)
			);
		} catch (ModelDuplicateException e) {
			// Lost a race against a concurrent registration of the same device_id.
			// AppCredentialProvider.createCredential already cleaned up the orphaned credential.
			tokenContext.getEvent().user(user).detail("device_id", deviceId).error(APP_SETUP_DUPLICATE_DEVICE_ID);
			authSession.setAuthNote("duplicateDeviceId", Boolean.toString(true));
			authSession.setAuthNote(StatusResourceProvider.READY, Boolean.toString(true));
			return Response.status(400).build();
		}

		EventBuilder event = tokenContext.getEvent().clone().event(EventType.UPDATE_CREDENTIAL)
			.user(user)
			.detail(Details.CREDENTIAL_TYPE, AppCredentialModel.TYPE)
			.detail("device_id", deviceId);
		if (isOverwrite) {
			event.detail("replaced_credential_id", existingIndex.getCredentialId());
		}
		event.success();

		authSession.setAuthNote("appSetupSuccessful", Boolean.toString(true));
		authSession.setAuthNote(StatusResourceProvider.READY, Boolean.toString(true));

		return Response.status(201).build();
	}

	@Override
	public boolean canUseTokenRepeatedly(AppSetupActionToken token, ActionTokenContext<AppSetupActionToken> tokenContext) {
		return false;
	}
}
