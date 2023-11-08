package netzbegruenung.keycloak.app.rest;

import netzbegruenung.keycloak.app.AuthenticationUtil;
import netzbegruenung.keycloak.app.credentials.AppCredentialModel;
import netzbegruenung.keycloak.app.dto.ChallengeConverter;
import netzbegruenung.keycloak.app.jpa.Challenge;
import org.jboss.logging.Logger;
import org.keycloak.common.util.Time;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.UserModel;
import org.keycloak.models.jpa.entities.RealmEntity;

import jakarta.persistence.EntityManager;
import jakarta.persistence.NoResultException;
import jakarta.persistence.NonUniqueResultException;
import jakarta.persistence.TypedQuery;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.*;

import java.util.*;
import java.util.stream.Collector;
import java.util.stream.Collectors;

public class ChallengeResource {

	private final KeycloakSession session;

	private final Logger logger = Logger.getLogger(ChallengeResource.class);

	public final static String CHALLENGE_REJECTED = "challenge_rejected";

	public final static String INTERNAL_ERROR = "internal_error";

	public ChallengeResource(KeycloakSession session) {
		this.session = session;
	}

	@GET
	@Produces(MediaType.APPLICATION_JSON)
	public Response getChallenges(@HeaderParam("Signature") List<String> signatureHeader, @QueryParam("device_id") String deviceId) {
		Map<String, String> signatureMap = AuthenticationUtil.getSignatureMap(signatureHeader);
		if (signatureMap == null) {
			return Response
				.status(Response.Status.BAD_REQUEST)
				.entity(new Message(CHALLENGE_REJECTED, "Missing, incomplete or invalid signature header"))
				.build();
		}

		EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
		RealmEntity realm = em.getReference(RealmEntity.class, session.getContext().getRealm().getId());

		TypedQuery<Challenge> query = em.createNamedQuery("Challenge.findByRealmAndDeviceId", Challenge.class);
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
				.type(MediaType.APPLICATION_JSON_TYPE)
				.entity(new Message(INTERNAL_ERROR, "Internal server error"))
				.build();

		} catch (Throwable e) {
			logger.error("Failed to get app authenticator challenge for device ID: " + deviceId, e);
			return Response
				.status(Response.Status.INTERNAL_SERVER_ERROR)
				.type(MediaType.APPLICATION_JSON_TYPE)
				.entity(new Message(INTERNAL_ERROR, "Internal server error"))
				.build();
		}

		Long actionTokenLifespan = (long) session.getContext().getRealm().getActionTokenGeneratedByUserLifespan() * 1000L;

		if (Time.currentTimeMillis() > challenge.getUpdatedTimestamp() + actionTokenLifespan
				|| Time.currentTimeMillis() > Long.parseLong(signatureMap.get("created")) + actionTokenLifespan) {
			return Response
				.status(Response.Status.FORBIDDEN)
				.entity(new Message(CHALLENGE_REJECTED, "Challenge expired"))
				.build();
		}

		try {
			UserModel user = session.users().getUserById(session.getContext().getRealm(), challenge.getUser().getId());
			AppCredentialModel appCredential = user.credentialManager()
				.getStoredCredentialsByTypeStream(AppCredentialModel.TYPE)
				.map(AppCredentialModel::createFromCredentialModel)
				.filter(c -> c.getAppCredentialData().getDeviceId().equals(deviceId))
				.collect(toSingleton());

			Map<String, String> signatureStringMap = new LinkedHashMap<>();
			signatureStringMap.put("created", signatureMap.get("created"));

			boolean verified = AuthenticationUtil.verifyChallenge(
				user,
				appCredential.getAppCredentialData(),
				AuthenticationUtil.getSignatureString(signatureStringMap),
				signatureMap.get("signature")
			);

			if (!verified) {
				return Response
					.status(Response.Status.FORBIDDEN)
					.entity(new Message(CHALLENGE_REJECTED, "Invalid signature"))
					.build();
			}

			return Response
				.ok(Arrays.asList(ChallengeConverter.getChallengeDto(challenge)))
				.build();

		} catch (IllegalStateException e) {
			logger.error(
				String.format(
					"Failed to get app authenticator challenge: duplicate app credentials detected for device ID [%s] user [%s]",
					deviceId,
					challenge.getUser().getUsername()
				),
				e
			);
			return Response
				.status(Response.Status.INTERNAL_SERVER_ERROR)
				.type(MediaType.APPLICATION_JSON_TYPE)
				.entity(new Message(INTERNAL_ERROR, "Internal server error"))
				.build();
		} catch (IndexOutOfBoundsException e) {
			logger.error(
				String.format(
					"Failed to get app authenticator challenge: no app credentials found for device ID [%s] user [%s]",
					deviceId,
					challenge.getUser().getUsername()
				),
				e
			);
			return Response
				.status(Response.Status.INTERNAL_SERVER_ERROR)
				.type(MediaType.APPLICATION_JSON_TYPE)
				.entity(new Message(INTERNAL_ERROR, "Internal server error"))
				.build();
		}
	}

	private <T> Collector<T, ?, T> toSingleton() throws IllegalStateException, IndexOutOfBoundsException {
		return Collectors.collectingAndThen(
			Collectors.toList(),
			list -> {
				if (list.size() > 1) {
					throw new IllegalStateException();
				}
				return list.get(0);
			}
		);
	}
}
