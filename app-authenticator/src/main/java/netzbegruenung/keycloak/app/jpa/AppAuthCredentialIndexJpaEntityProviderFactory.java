package netzbegruenung.keycloak.app.jpa;

import jakarta.persistence.EntityManager;
import netzbegruenung.keycloak.app.credentials.AppCredentialModel;
import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.connections.jpa.entityprovider.JpaEntityProvider;
import org.keycloak.connections.jpa.entityprovider.JpaEntityProviderFactory;
import org.keycloak.credential.CredentialModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.ModelDuplicateException;
import org.keycloak.models.jpa.entities.CredentialEntity;
import org.keycloak.models.jpa.entities.RealmEntity;
import org.keycloak.models.utils.KeycloakModelUtils;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class AppAuthCredentialIndexJpaEntityProviderFactory implements JpaEntityProviderFactory {

	protected static final String ID = "app-auth-credential-index-entity-provider";

	private static final Logger logger = Logger.getLogger(AppAuthCredentialIndexJpaEntityProviderFactory.class);

	@Override
	public JpaEntityProvider create(KeycloakSession keycloakSession) {
		return new AppAuthCredentialIndexJpaEntityProvider();
	}

	@Override
	public void init(Config.Scope scope) {

	}

	// One-time, idempotent backfill for pre-existing app credentials; the NOT EXISTS anti-join
	// below makes steady-state restarts a no-op.
	//
	// Flushed manually every BATCH_SIZE rows instead of via Keycloak's own STORAGE_BATCH_ENABLED,
	// since that mechanism's internal flush bypasses EntityManagerProxy's exception conversion and
	// would misattribute a constraint violation to the wrong row. No em.clear() after the flush -
	// that would defeat the join fetch below by forcing a re-select per remaining row.
	private static final int BATCH_SIZE = 100;

	@Override
	public void postInit(KeycloakSessionFactory keycloakSessionFactory) {
		KeycloakModelUtils.runJobInTransaction(keycloakSessionFactory, session -> {
			EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();

			// join fetch c.user: CredentialEntity.user is lazy, and every row below needs
			// credential.getUser().getRealmId() - without this, that's an N+1 lazy-load
			// (one extra SELECT per unindexed credential) instead of one join.
			List<CredentialEntity> unindexedCredentials = em.createQuery(
				"select c from CredentialEntity c join fetch c.user where c.type = :type and not exists "
					+ "(select 1 from AppAuthCredentialIndex i where i.credentialId = c.id)",
				CredentialEntity.class)
				.setParameter("type", AppCredentialModel.TYPE)
				.getResultList();

			if (unindexedCredentials.isEmpty()) {
				return;
			}

			Set<String> claimedRealmDeviceKeys = new HashSet<>();
			for (Object[] row : em.createQuery(
				"select i.realm.id, i.deviceId from AppAuthCredentialIndex i", Object[].class)
				.getResultList()) {
				claimedRealmDeviceKeys.add(row[0] + "|" + row[1]);
			}

			List<String> pendingBatchCredentialIds = new ArrayList<>();
			for (CredentialEntity credential : unindexedCredentials) {
				try {
					CredentialModel rawModel = new CredentialModel();
					rawModel.setCredentialData(credential.getCredentialData());
					String deviceId = AppCredentialModel.createFromCredentialModel(rawModel).getAppCredentialData().getDeviceId();

					String realmId = credential.getUser().getRealmId();
					String key = realmId + "|" + deviceId;
					if (!claimedRealmDeviceKeys.add(key)) {
						logger.warnf(
							"Skipped backfilling device index for app credential [%s]: device_id [%s] is already claimed by another credential in realm [%s]",
							credential.getId(), deviceId, realmId);
						continue;
					}

					AppAuthCredentialIndex index = new AppAuthCredentialIndex();
					index.setRealm(em.getReference(RealmEntity.class, realmId));
					index.setUser(credential.getUser());
					index.setDeviceId(deviceId);
					index.setCredentialId(credential.getId());
					em.persist(index);
					pendingBatchCredentialIds.add(credential.getId());
				} catch (Exception e) {
					logger.warnf(e, "Skipped backfilling device index for app credential [%s]: could not read credentialData", credential.getId());
					continue;
				}

				if (pendingBatchCredentialIds.size() >= BATCH_SIZE) {
					flushBatch(em, pendingBatchCredentialIds);
				}
			}
			flushBatch(em, pendingBatchCredentialIds);
		});
	}

	private void flushBatch(EntityManager em, List<String> pendingBatchCredentialIds) {
		if (pendingBatchCredentialIds.isEmpty()) {
			return;
		}
		try {
			em.flush();
		} catch (ModelDuplicateException e) {
			logger.warnf(e, "Skipped backfilling device index for one or more app credentials in %s: "
				+ "device_id already claimed (concurrent backfill on another node?)", pendingBatchCredentialIds);
		} catch (Exception e) {
			logger.warnf(e, "Skipped backfilling device index for one or more app credentials in %s: "
				+ "failed to flush this batch", pendingBatchCredentialIds);
		} finally {
			pendingBatchCredentialIds.clear();
		}
	}

	@Override
	public void close() {

	}

	@Override
	public String getId() {
		return ID;
	}
}
