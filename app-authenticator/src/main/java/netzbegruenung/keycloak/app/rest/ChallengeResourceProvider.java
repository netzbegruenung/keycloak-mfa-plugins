package netzbegruenung.keycloak.app.rest;

import jakarta.persistence.EntityManager;
import jakarta.persistence.NoResultException;
import jakarta.persistence.NonUniqueResultException;
import jakarta.persistence.TypedQuery;
import jakarta.ws.rs.*;
import jakarta.ws.rs.container.AsyncResponse;
import jakarta.ws.rs.container.Suspended;
import jakarta.ws.rs.core.GenericType;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import netzbegruenung.keycloak.app.AuthenticationUtil;
import netzbegruenung.keycloak.app.dto.ChallengeConverter;
import netzbegruenung.keycloak.app.dto.ChallengeDto;
import netzbegruenung.keycloak.app.jpa.Challenge;
import org.jboss.logging.Logger;
import org.keycloak.common.util.Time;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.*;
import org.keycloak.models.jpa.entities.RealmEntity;
import org.keycloak.services.resource.RealmResourceProvider;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.*;

import static org.keycloak.models.utils.KeycloakModelUtils.runJobInTransaction;

public class ChallengeResourceProvider implements RealmResourceProvider {

	private final KeycloakSession session;
	private final EntityManager em;
	private final Logger logger = Logger.getLogger(ChallengeResourceProvider.class);
	private final KeycloakSessionFactory sessionFactory;
	private final AppCredentialService appCredentialService;

	private final static ConcurrentHashMap<String, DeviceConnection> listeners = new ConcurrentHashMap<>();
	public final static ScheduledThreadPoolExecutor scheduler = new ScheduledThreadPoolExecutor(1);
	public final static String CHALLENGE_REJECTED = "challenge_rejected";
	public final static String CHALLENGE_EXPIRED = "challenge_expired";
	public final static String INTERNAL_ERROR = "internal_error";
	private final static long EXPIRATION_TIME = 120;
	private final static long RESPONSE_TIMEOUT = 60;

	public ChallengeResourceProvider(KeycloakSession session) {
		this.session = session;
		this.em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
		this.sessionFactory = session.getKeycloakSessionFactory();
		this.appCredentialService = new AppCredentialService(session);
	}

	@Override
	public Object getResource() {
		return this;
	}

	@Override
	public void close() {

	}

	@GET
	@Produces(MediaType.APPLICATION_JSON)
	public Response getChallenges(@HeaderParam("Signature") List<String> signatureHeader) {
		Map<String, String> signatureMap = AuthenticationUtil.getSignatureMap(signatureHeader);
		return getChallengesResponse(signatureMap);
	}

	private Response getChallengesResponse(Map<String, String> signatureMap) {
		if (signatureMap == null) {
			return Response
				.status(Response.Status.BAD_REQUEST)
				.entity(new Message(CHALLENGE_REJECTED, "Missing, incomplete or invalid signature header"))
				.build();
		}

		try {
			appCredentialService.getVerifiedCredentialContainer(signatureMap);
		} catch (VerificationErrorResponseException e) {
			return e.getResponse();
		}

		String deviceId = signatureMap.get("keyId");

		TypedQuery<Challenge> query = em.createNamedQuery("Challenge.findByRealmAndDeviceId", Challenge.class);
		RealmEntity realm = em.getReference(RealmEntity.class, session.getContext().getRealm().getId());
		query.setParameter("realm", realm);
		query.setParameter("deviceId", deviceId);
		Challenge challenge;

		try {
			challenge = query.getSingleResult();

		} catch (NoResultException e) {
			return Response
				.status(Response.Status.OK)
				.entity(Collections.emptyList())
				.build();

		} catch (NonUniqueResultException e) {
			logger.error("Failed to get app authenticator challenge: duplicate challenge detected for device ID: " + deviceId, e);
			return Response
				.status(Response.Status.INTERNAL_SERVER_ERROR)
				.entity(new Message(INTERNAL_ERROR, "Internal server error"))
				.build();

		} catch (Throwable e) {
			logger.error("Failed to get app authenticator challenge for device ID: " + deviceId, e);
			return Response
				.status(Response.Status.INTERNAL_SERVER_ERROR)
				.entity(new Message(INTERNAL_ERROR, "Internal server error"))
				.build();
		}

		if (Time.currentTime() > challenge.getExpiresAt()
			|| Long.parseLong(signatureMap.get("created")) < challenge.getUpdatedTimestamp() - 1000) {
			return Response
				.status(Response.Status.FORBIDDEN)
				.entity(new Message(CHALLENGE_EXPIRED, "Challenge expired"))
				.build();
		}

		return Response
			.ok(List.of(ChallengeConverter.getChallengeDto(challenge, session)))
			.build();
	}

	@GET
	@Path("async")
	@Produces(MediaType.APPLICATION_JSON)
	public void getChallengesAsync(@HeaderParam("Signature") List<String> signatureHeader, @Suspended AsyncResponse asyncResponse) {
		Map<String, String> signatureMap = AuthenticationUtil.getSignatureMap(signatureHeader);
		Response response = getChallengesResponse(signatureMap);

		if (!response.getStatusInfo().getFamily().equals(Response.Status.Family.SUCCESSFUL)) {
			if (response.getStatus() != 403) {
				asyncResponse.resume(response);
				return;
			}
			Message message = response.readEntity(Message.class);
			if (!message.error().equals(CHALLENGE_EXPIRED)) {
				asyncResponse.resume(response);
				return;
			}
		} else {
			List<ChallengeDto> challenges = response.readEntity(new GenericType<>() {
			});
			if (!challenges.isEmpty()) {
				asyncResponse.resume(response);
				return;
			}
		}


		String deviceId = signatureMap.get("keyId");
		asyncResponse.setTimeout(RESPONSE_TIMEOUT, TimeUnit.SECONDS);
		ScheduledFuture<?> evictionJob = scheduler.schedule(() -> {
			listeners.remove(deviceId);
		}, EXPIRATION_TIME, TimeUnit.SECONDS);

		DeviceConnection existingConnection = listeners.get(deviceId);
		if (existingConnection != null) {
			existingConnection.evictionJob().cancel(false);
			existingConnection.asyncResponse().cancel();
		}

		listeners.put(deviceId, new DeviceConnection(asyncResponse, evictionJob));
	}

	public void notifyListeners(Challenge challenge, RealmModel realm) {
		String deviceId = challenge.getDeviceId();
		DeviceConnection deviceConnection = listeners.get(deviceId);

		if (deviceConnection != null) {
			AsyncResponse asyncResponse = deviceConnection.asyncResponse();
			if (asyncResponse != null) {
				runJobInTransaction(sessionFactory, session -> {
					KeycloakContext context = session.getContext();

					context.setRealm(realm);
					asyncResponse.resume(Response
						.ok(List.of(ChallengeConverter.getChallengeDto(challenge, session)))
						.build()
					);
				});
			}
		}
	}

	private record DeviceConnection(AsyncResponse asyncResponse, ScheduledFuture<?> evictionJob) {
	}
}
