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
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collector;
import java.util.stream.Collectors;

public class ChallengeResource {

	private final KeycloakSession session;

	private final Logger logger = Logger.getLogger(ChallengeResource.class);

	public ChallengeResource(KeycloakSession session) {
		this.session = session;
	}

	@GET
	@Path("{deviceId}")
	@Produces(MediaType.APPLICATION_JSON)
	public Response getChallenges(@Context Request request, @Context HttpHeaders headers, final @Context UriInfo uriInfo, final @PathParam("deviceId") String deviceId) {
		Map<String, String> signatureMap = AuthenticationUtil.getSignatureMap(headers.getRequestHeader("Signature"));
		if (signatureMap == null) {
			logger.warnf("GET app authentication challenge rejected: missing, incomplete or invalid signature header for device ID [%s]", deviceId);
			return Response.status(Response.Status.BAD_REQUEST).build();
		}

		EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
		RealmEntity realm = em.getReference(RealmEntity.class, session.getContext().getRealm().getId());

		TypedQuery<Challenge> query = em.createNamedQuery("Challenge.findByRealmAndDeviceId", Challenge.class);
		query.setParameter("realm", realm);
		query.setParameter("deviceId", signatureMap.get("keyId"));
		Challenge challenge;

		try {
			challenge = query.getSingleResult();

		} catch (NoResultException e) {
			logger.warn("No challenge found for device ID " + deviceId, e);
			return Response.status(Response.Status.NOT_FOUND).build();

		} catch (NonUniqueResultException e) {
			logger.error("Failed to get app authenticator challenge: duplicate challenge detected for device ID: " + deviceId, e);
			return Response.status(Response.Status.INTERNAL_SERVER_ERROR).type(MediaType.APPLICATION_JSON_TYPE).build();

		} catch (Throwable e) {
			logger.error("Failed to get app authenticator challenge for device ID: " + deviceId, e);
			return Response.status(Response.Status.INTERNAL_SERVER_ERROR).type(MediaType.APPLICATION_JSON_TYPE).build();
		}

		if (Time.currentTimeMillis() > challenge.getUpdatedTimestamp() + (long) session.getContext().getRealm().getActionTokenGeneratedByUserLifespan() * 1000L) {
			logger.warnf(
				"Failed to get app authenticator challenge: challenge expired user [%s] device [%s]",
				challenge.getUser().getUsername(),
				challenge.getDeviceId()
			);
			return Response.status(Response.Status.FORBIDDEN).build();
		}

		try {
			UserModel user = session.users().getUserById(session.getContext().getRealm(), challenge.getUser().getId());
			AppCredentialModel appCredential = user.credentialManager()
				.getStoredCredentialsByTypeStream(AppCredentialModel.TYPE)
				.map(AppCredentialModel::createFromCredentialModel)
				.filter(c -> c.getAppCredentialData().getDeviceId().equals(deviceId))
				.collect(toSingleton());

			Map<String, String> signatureStringMap = new HashMap<>();
			String requestTarget = request.getMethod().toLowerCase()
					.concat("_")
					.concat(uriInfo.getPath());
			signatureStringMap.put("request-target", requestTarget);
			signatureStringMap.put("created", signatureMap.get("created"));

			boolean verified = AuthenticationUtil.verifyChallenge(
				user,
				appCredential.getAppCredentialData(),
				AuthenticationUtil.getSignatureString(signatureStringMap).getBytes(),
				signatureMap.get("signature")
			);

			if (!verified) {
				return Response.status(Response.Status.FORBIDDEN).build();
			}

			return Response.ok(ChallengeConverter.getChallengeDto(challenge)).build();

		} catch (IllegalStateException e) {
			logger.error(
				String.format(
					"Failed to get app authenticator challenge: duplicate app credentials detected for device ID [%s] user [%s]",
					deviceId,
					challenge.getUser().getUsername()
				),
				e
			);
			return Response.status(Response.Status.INTERNAL_SERVER_ERROR).type(MediaType.APPLICATION_JSON_TYPE).build();
		} catch (IndexOutOfBoundsException e) {
			logger.warn(
				String.format(
					"Failed to get app authenticator challenge: no app credentials found for device ID [%s] user [%s]",
					deviceId,
					challenge.getUser().getUsername()
				),
				e
			);
			return Response.status(Response.Status.CONFLICT).type(MediaType.APPLICATION_JSON_TYPE).build();
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
