package netzbegruenung.keycloak.app.rest;

import jakarta.persistence.EntityManager;
import jakarta.persistence.NoResultException;
import jakarta.persistence.NonUniqueResultException;
import jakarta.ws.rs.core.Response;
import netzbegruenung.keycloak.app.AuthenticationUtil;
import netzbegruenung.keycloak.app.credentials.AppCredentialModel;
import netzbegruenung.keycloak.app.jpa.AppAuthCredentialIndex;
import org.jboss.logging.Logger;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.credential.CredentialModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.jpa.entities.RealmEntity;
import org.keycloak.models.jpa.entities.UserEntity;

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
		RealmModel realm = session.getContext().getRealm();

		AppAuthCredentialIndex index;
		try {
			index = em.createNamedQuery("AppAuthCredentialIndex.findByRealmAndDeviceId", AppAuthCredentialIndex.class)
				.setParameter("realm", em.getReference(RealmEntity.class, realm.getId()))
				.setParameter("deviceId", deviceId)
				.getSingleResult();
		} catch (NoResultException e) {
			throw new VerificationErrorResponseException(Response
				.status(Response.Status.CONFLICT)
				.entity(new Message(NO_CREDENTIAL, "App credential does not exist"))
				.build());
		} catch (NonUniqueResultException e) {
			logger.error("Failed to get app credential index: duplicate index entries detected for device ID: " + deviceId, e);
			throw new VerificationErrorResponseException(Response
				.status(Response.Status.INTERNAL_SERVER_ERROR)
				.entity(new Message("internal_error", "Internal server error"))
				.build());
		}

		UserModel user = session.users().getUserById(realm, index.getUser().getId());
		CredentialModel credential = user == null ? null : user.credentialManager().getStoredCredentialById(index.getCredentialId());
		if (credential == null) {
			throw new VerificationErrorResponseException(Response
				.status(Response.Status.CONFLICT)
				.entity(new Message(NO_CREDENTIAL, "App credential does not exist"))
				.build());
		}
		AppCredentialModel appCredential = AppCredentialModel.createFromCredentialModel(credential);

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
				.status(Response.Status.UNAUTHORIZED)
				.entity(new Message(CHALLENGE_REJECTED, "Invalid signature"))
				.build());
		}
		return new VerifiedCredentialContainer(user, credential, appCredential);
	}

	/**
	 * Realm-wide check, required because (realm_id, device_id) is a DB-level unique
	 * constraint on AppAuthCredentialIndex - registration must pre-check across all users,
	 * not just the requesting user's own credentials. Reuses findByRealmAndDeviceId rather
	 * than a separate count query: the unique constraint guarantees at most one match, so
	 * NoResultException already tells us everything a count would.
	 */
	public boolean isDeviceIdRegistered(RealmModel realm, String deviceId) {
		try {
			em.createNamedQuery("AppAuthCredentialIndex.findByRealmAndDeviceId", AppAuthCredentialIndex.class)
				.setParameter("realm", em.getReference(RealmEntity.class, realm.getId()))
				.setParameter("deviceId", deviceId)
				.getSingleResult();
			return true;
		} catch (NoResultException e) {
			return false;
		}
	}

	/**
	 * Flushes immediately (rather than leaving the INSERT queued for a later, unrelated
	 * flush) so a (realm_id, device_id) unique-constraint violation - e.g. a concurrent
	 * registration racing on the same device_id - surfaces here as a {@link
	 * org.keycloak.models.ModelDuplicateException}, where the caller can handle it, instead
	 * of at some later, unrelated call site.
	 */
	public void indexCredential(RealmModel realm, UserModel user, String deviceId, String credentialId) {
		AppAuthCredentialIndex index = new AppAuthCredentialIndex();
		index.setRealm(em.getReference(RealmEntity.class, realm.getId()));
		index.setUser(em.getReference(UserEntity.class, user.getId()));
		index.setDeviceId(deviceId);
		index.setCredentialId(credentialId);
		em.persist(index);
		em.flush();
	}
}
