package netzbegruenung.keycloak.app.rest;

import jakarta.ws.rs.*;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.sse.Sse;
import jakarta.ws.rs.sse.SseEventSink;
import org.jboss.logging.Logger;
import org.keycloak.models.*;
import org.keycloak.services.managers.AuthenticationSessionManager;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.sessions.AuthenticationSessionModel;

public class StatusResourceProvider implements RealmResourceProvider {

	private final KeycloakSession session;

	private final Logger logger = Logger.getLogger(StatusResourceProvider.class);

	public final static String READY = "appAuthReady";

	private final static String UNAUTHORIZED = "Unauthorized";

	public StatusResourceProvider(KeycloakSession session) {
		this.session = session;
	}

	@Override
	public Object getResource() {
		return this;
	}

	@Override
	public void close() {

	}

	@GET
	@Produces(MediaType.SERVER_SENT_EVENTS)
	public void getAppAuthStatus(@Context SseEventSink sseEventSink,
							  @Context Sse sse,
							  @QueryParam(Constants.CLIENT_ID) String clientId,
							  @QueryParam(Constants.TAB_ID) String tabId) throws InterruptedException {
		RealmModel realm = session.getContext().getRealm();
		ClientModel client = null;
		if (clientId != null)
			client = realm.getClientByClientId(clientId);


		AuthenticationSessionManager authSessionManager = new AuthenticationSessionManager(session);
		AuthenticationSessionModel authSession;
		int counter = 0;

		while (true) {
			authSession = authSessionManager.getCurrentAuthenticationSession(realm, client, tabId);

			if (authSession == null)
				throw new NotAuthorizedException(UNAUTHORIZED);

			UserModel user = authSession.getAuthenticatedUser();

			if (authSession.getAuthNote(READY) != null) {
				authSession.setAuthNote(READY, null);

				try {
					sseEventSink.send(sse.newEvent("status", "ready"))
						.toCompletableFuture()
						.get();
				} catch (Exception e) {
					logger.errorf(e, "Failed to send authentication status for user %s", user == null ? "null" : user.getId());
				} finally {
					break;
				}
			}

			if (++counter % 30 == 0) {
				try {
					sseEventSink.send(sse.newEvent("status", "keep-alive"))
						.toCompletableFuture()
						.get();
				} catch (Exception e) {
					// should be debug
					logger.infof(e, "Failed to send keep alive message for user %s", user == null ? "null" : user.getId());
					break;
				}
			}

			Thread.sleep(1000);
		}

		sseEventSink.close();
	}

}
