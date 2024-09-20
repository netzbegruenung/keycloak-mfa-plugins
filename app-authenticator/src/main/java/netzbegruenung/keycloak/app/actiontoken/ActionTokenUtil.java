package netzbegruenung.keycloak.app.actiontoken;

import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationProcessor;
import org.keycloak.authentication.actiontoken.DefaultActionToken;
import org.keycloak.common.util.Time;
import org.keycloak.models.*;
import org.keycloak.services.Urls;
import org.keycloak.services.managers.AuthenticationSessionManager;
import org.keycloak.sessions.AuthenticationSessionCompoundId;
import org.keycloak.sessions.AuthenticationSessionModel;

import jakarta.ws.rs.core.UriInfo;
import java.lang.reflect.InvocationTargetException;
import java.net.URI;

public class ActionTokenUtil {

	final static private Logger logger = Logger.getLogger(ActionTokenUtil.class);

	public static AuthenticationSessionModel getOriginalAuthSession(KeycloakSession session, RealmModel realm, String originalAuthSessionId) {
		AuthenticationSessionManager asm = new AuthenticationSessionManager(session);
		AuthenticationSessionCompoundId compoundId = AuthenticationSessionCompoundId.encoded(originalAuthSessionId);
		ClientModel originalClient = realm.getClientById(compoundId.getClientUUID());
		return asm.getAuthenticationSessionByIdAndClient(
			realm,
			compoundId.getRootSessionId(),
			originalClient,
			compoundId.getTabId()
		);
	}

	public static URI createActionToken(Class<?> actionTokenClass, AuthenticationSessionModel authSession, KeycloakSession session, RealmModel realm, UserModel user, UriInfo uriInfo) {
		try {
			final String clientId = authSession.getClient().getClientId();
			DefaultActionToken token = (DefaultActionToken) actionTokenClass.getDeclaredConstructor(String.class, Integer.class, String.class, String.class).newInstance(
				user.getId(),
				Time.currentTime() + realm.getActionTokenGeneratedByUserLifespan(),
				AuthenticationSessionCompoundId.fromAuthSession(authSession).getEncodedId(),
				clientId
			);
			return Urls
				.actionTokenBuilder(
					uriInfo.getBaseUri(),
					token.serialize(session, realm, uriInfo),
					clientId,
					authSession.getTabId(),
					AuthenticationProcessor.getClientData(session, authSession)
				)
				.build(realm.getName());
		} catch (NoSuchMethodException | InstantiationException | IllegalAccessException | InvocationTargetException e) {
			throw new RuntimeException(e);
		}

	}
}
