package netzbegruenung.keycloak.app.rest;

import jakarta.persistence.criteria.CriteriaBuilder;
import jakarta.persistence.criteria.CriteriaQuery;
import jakarta.persistence.criteria.Root;
import netzbegruenung.keycloak.app.AuthenticationUtil;
import netzbegruenung.keycloak.app.credentials.AppCredentialModel;
import netzbegruenung.keycloak.app.dto.ChallengeConverter;
import netzbegruenung.keycloak.app.jpa.Challenge;
import org.jboss.logging.Logger;
import org.keycloak.common.util.Base64;
import org.keycloak.common.util.Time;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.credential.CredentialModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.UserModel;
import org.keycloak.models.jpa.entities.CredentialEntity;
import org.keycloak.models.jpa.entities.RealmEntity;

import jakarta.persistence.EntityManager;
import jakarta.persistence.NoResultException;
import jakarta.persistence.NonUniqueResultException;
import jakarta.persistence.TypedQuery;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.*;

import java.util.*;

public class ChallengeResource {

	private final KeycloakSession session;

	private final EntityManager em;

	private final Logger logger = Logger.getLogger(ChallengeResource.class);

	public final static String CHALLENGE_REJECTED = "challenge_rejected";

	public final static String INTERNAL_ERROR = "internal_error";

	public final static String NO_CREDENTIAL = "no_credential";

	public ChallengeResource(KeycloakSession session) {
		this.session = session;
		this.em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
	}

	@GET
	@Produces(MediaType.APPLICATION_JSON)
	public Response getChallenges(@HeaderParam("Signature") List<String> signatureHeader) {
		Map<String, String> signatureMap = AuthenticationUtil.getSignatureMap(signatureHeader);
		if (signatureMap == null) {
			return Response
				.status(Response.Status.BAD_REQUEST)
				.entity(new Message(CHALLENGE_REJECTED, "Missing, incomplete or invalid signature header"))
				.build();
		}

		String deviceId = signatureMap.get("keyId");

		CriteriaBuilder cb = em.getCriteriaBuilder();
		CriteriaQuery<CredentialEntity> criteria = cb.createQuery(CredentialEntity.class);
		Root<CredentialEntity> root = criteria.from(CredentialEntity.class);
		criteria.where(
			cb.equal(root.get("type"), AppCredentialModel.TYPE),
			cb.like(root.get("credentialData"), String.format("%%\"deviceId\":\"%s\"%%", deviceId))
		);

		TypedQuery<CredentialEntity> criteriaQuery = em.createQuery(criteria);
		CredentialEntity credentialEntity;

		try {
			credentialEntity = criteriaQuery.getSingleResult();
		} catch (NoResultException e) {
			return Response
				.status(Response.Status.CONFLICT)
				.entity(new Message(NO_CREDENTIAL, "App credential does not exist"))
				.build();
		} catch (NonUniqueResultException e) {
			logger.error("Failed to get app credentials: duplicate credentials detected for device ID: " + deviceId, e);
			return Response
				.status(Response.Status.INTERNAL_SERVER_ERROR)
				.entity(new Message(INTERNAL_ERROR, "Internal server error"))
				.build();
		}

		AppCredentialModel appCredential = AppCredentialModel.createFromCredentialModel(toModel(credentialEntity));
		UserModel user = session.users().getUserById(session.getContext().getRealm(), credentialEntity.getUser().getId());

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
				.entity(new Message(CHALLENGE_REJECTED, "Challenge expired"))
				.build();
		}

		return Response
			.ok(List.of(ChallengeConverter.getChallengeDto(challenge, session)))
			.build();
	}

	CredentialModel toModel(CredentialEntity entity) {
		CredentialModel model = new CredentialModel();
		model.setId(entity.getId());
		model.setType(entity.getType());
		model.setCreatedDate(entity.getCreatedDate());
		model.setUserLabel(entity.getUserLabel());

		// Backwards compatibility - users from previous version still have "salt" in the DB filled.
		// We migrate it to new secretData format on-the-fly
		if (entity.getSalt() != null) {
			String newSecretData = entity.getSecretData().replace("__SALT__", Base64.encodeBytes(entity.getSalt()));
			entity.setSecretData(newSecretData);
			entity.setSalt(null);
		}

		model.setSecretData(entity.getSecretData());
		model.setCredentialData(entity.getCredentialData());
		return model;
	}
}
