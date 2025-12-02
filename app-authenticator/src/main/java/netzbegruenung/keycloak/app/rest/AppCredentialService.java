package netzbegruenung.keycloak.app.rest;

import jakarta.persistence.EntityManager;
import jakarta.persistence.NoResultException;
import jakarta.persistence.NonUniqueResultException;
import jakarta.persistence.TypedQuery;
import jakarta.persistence.criteria.CriteriaBuilder;
import jakarta.persistence.criteria.CriteriaQuery;
import jakarta.persistence.criteria.Root;
import jakarta.ws.rs.core.Response;
import netzbegruenung.keycloak.app.AuthenticationUtil;
import netzbegruenung.keycloak.app.credentials.AppCredentialModel;
import org.jboss.logging.Logger;
import org.keycloak.common.util.Base64;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.credential.CredentialModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.UserModel;
import org.keycloak.models.jpa.entities.CredentialEntity;


import java.util.LinkedHashMap;
import java.util.Map;

public class AppCredentialService {

	private final KeycloakSession session;
	private final EntityManager em;
	private final Logger logger = Logger.getLogger(AppCredentialService.class);
	public final static String NO_CREDENTIAL = "no_credential";
	public final static String CHALLENGE_REJECTED = "challenge_rejected";

	public AppCredentialService(KeycloakSession session) {
		this.session = session;
		this.em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
	}

	public VerifiedCredentialContainer getVerifiedCredentialContainer(Map<String, String> signatureMap) throws VerificationErrorResponseException {
		String deviceId = signatureMap.get("keyId");

		CredentialEntity credentialEntity;
		try {
			credentialEntity = getCredentialEntityByDeviceId(deviceId);
		} catch (NoResultException e) {
			throw new VerificationErrorResponseException(Response
				.status(Response.Status.CONFLICT)
				.entity(new Message(NO_CREDENTIAL, "App credential does not exist"))
				.build());
		} catch (NonUniqueResultException e) {
			logger.error("Failed to get app credentials: duplicate credentials detected for device ID: " + deviceId, e);
			throw new VerificationErrorResponseException(Response
				.status(Response.Status.INTERNAL_SERVER_ERROR)
				.entity(new Message("internal_error", "Internal server error"))
				.build());
		}

		CredentialModel credential = toModel(credentialEntity);
		AppCredentialModel appCredential = AppCredentialModel.createFromCredentialModel(credential);
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
			throw new VerificationErrorResponseException(Response
				.status(Response.Status.FORBIDDEN)
				.entity(new Message(CHALLENGE_REJECTED, "Invalid signature"))
				.build());
		}
		return new VerifiedCredentialContainer(user, credential, appCredential);
	}

	private CredentialEntity getCredentialEntityByDeviceId(String deviceId) {
		CriteriaBuilder cb = em.getCriteriaBuilder();
		CriteriaQuery<CredentialEntity> criteria = cb.createQuery(CredentialEntity.class);
		Root<CredentialEntity> root = criteria.from(CredentialEntity.class);
		criteria.where(
			cb.equal(root.get("type"), AppCredentialModel.TYPE),
			cb.like(root.get("credentialData"), String.format("%%\"deviceId\":\"%s\"%%", deviceId))
		);

		TypedQuery<CredentialEntity> criteriaQuery = em.createQuery(criteria);
		return criteriaQuery.getSingleResult();
	}

	private CredentialModel toModel(CredentialEntity entity) {
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
