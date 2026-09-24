package netzbegruenung.keycloak.app.actiontoken;

import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceException;
import netzbegruenung.keycloak.app.AppAuthenticator;
import netzbegruenung.keycloak.app.AppCredentialProvider;
import netzbegruenung.keycloak.app.AppCredentialProviderFactory;
import netzbegruenung.keycloak.app.AuthenticationUtil;
import netzbegruenung.keycloak.app.credentials.AppCredentialData;
import netzbegruenung.keycloak.app.credentials.AppCredentialModel;
import netzbegruenung.keycloak.app.rest.StatusResourceProvider;
import org.jboss.logging.Logger;
import org.keycloak.authentication.actiontoken.AbstractActionTokenHandler;
import org.keycloak.authentication.actiontoken.ActionTokenContext;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.credential.CredentialModel;
import org.keycloak.credential.CredentialProvider;
import org.keycloak.events.Errors;
import org.keycloak.events.EventType;
import org.keycloak.models.jpa.entities.RealmEntity;
import org.keycloak.services.messages.Messages;
import org.keycloak.sessions.AuthenticationSessionModel;

import jakarta.ws.rs.core.Response;
import java.util.HashMap;
import java.util.Map;

public class AppAuthActionTokenHandler extends AbstractActionTokenHandler<AppAuthActionToken> {

	private final Logger logger = Logger.getLogger(AppAuthActionTokenHandler.class);
	// Dedicated EXECUTE_ACTION_TOKEN_ERROR event errors, so failed app challenge responses are distinguishable
	// from Keycloak's own action tokens (verify email, reset password, ...)
	public static final String APP_AUTH_INVALID_SIGNATURE = "app_auth_invalid_signature";
	public static final String APP_AUTH_SESSION_EXPIRED = "app_auth_session_expired";

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
		AuthenticationSessionModel authSession = ActionTokenUtil.getOriginalAuthSession(
			tokenContext.getSession(),
			tokenContext.getRealm(),
			token.getOriginalAuthenticationSessionId()
		);

		if (authSession == null) {
			tokenContext.getEvent().user(token.getUserId()).error(APP_AUTH_SESSION_EXPIRED);
			return Response.status(Response.Status.FORBIDDEN).build();
		}

		String authSessionGranted = authSession.getAuthNote(AppAuthenticator.APP_AUTH_GRANTED_NOTE);

		if (authSessionGranted != null && !Boolean.parseBoolean(authSessionGranted)) {
			// once rejected, always rejected
			return Response.status(Response.Status.FORBIDDEN).build();
		}

		Map<String, String> signatureMap = AuthenticationUtil.getSignatureMap(tokenContext.getRequest().getHttpHeaders().getRequestHeader(AuthenticationUtil.SIGNATURE_HEADER));
		if (signatureMap == null) {
			tokenContext.getEvent().user(token.getUserId()).error(APP_AUTH_INVALID_SIGNATURE);
			authSession.setAuthNote(StatusResourceProvider.READY, Boolean.toString(true));
			return Response.status(Response.Status.BAD_REQUEST).build();
		}

		AppCredentialProvider appCredentialProvider = (AppCredentialProvider) tokenContext
			.getSession()
			.getProvider(CredentialProvider.class, AppCredentialProviderFactory.PROVIDER_ID);
		CredentialModel appCredentialModel = appCredentialProvider
			.getCredentialModel(authSession.getAuthenticatedUser(), authSession.getAuthNote("credentialId"));

		AppCredentialData appCredentialData = AppCredentialModel.createFromCredentialModel(appCredentialModel).getAppCredentialData();

		Map<String, String> signatureStringMap = new HashMap<>();
		signatureStringMap.put("created", signatureMap.get("created"));
		signatureStringMap.put("secret", authSession.getAuthNote("secret"));
		signatureStringMap.put("granted", signatureMap.get("granted"));

		boolean verified = AuthenticationUtil.verifyChallenge(
			authSession.getAuthenticatedUser(),
			appCredentialData,
			AuthenticationUtil.getSignatureString(signatureStringMap),
			signatureMap.get("signature")
		);

		if (!verified) {
			tokenContext.getEvent()
				.user(token.getUserId())
				.detail("device_id", appCredentialData.getDeviceId())
				.error(APP_AUTH_INVALID_SIGNATURE);
			authSession.setAuthNote(StatusResourceProvider.READY, Boolean.toString(true));
			return Response.status(Response.Status.FORBIDDEN).build();
		}

		if (!Boolean.parseBoolean(signatureMap.get("granted"))) {
			authSession.setAuthNote(AppAuthenticator.APP_AUTH_GRANTED_NOTE, Boolean.toString(false));
		} else {
			authSession.setAuthNote(AppAuthenticator.APP_AUTH_GRANTED_NOTE, Boolean.toString(true));
		}

		authSession.setAuthNote(StatusResourceProvider.READY, Boolean.toString(true));

		try {
			EntityManager em = tokenContext.getSession().getProvider(JpaConnectionProvider.class).getEntityManager();
			RealmEntity realm = em.getReference(RealmEntity.class, tokenContext.getRealm().getId());
			em.createNamedQuery("Challenge.deleteByRealmAndDeviceId")
				.setParameter("realm", realm)
				.setParameter("deviceId", appCredentialData.getDeviceId())
				.executeUpdate();
		} catch (PersistenceException e) {
			logger.error(String.format("Failed to delete challenge for device ID %s", appCredentialData.getDeviceId()), e);
		}

		return Response.status(Response.Status.NO_CONTENT).build();
	}

	@Override
	public boolean canUseTokenRepeatedly(AppAuthActionToken token, ActionTokenContext<AppAuthActionToken> tokenContext) {
		return false;
	}
}
