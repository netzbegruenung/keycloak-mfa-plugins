package netzbegruenung.keycloak.app;

import jakarta.ws.rs.core.UriBuilder;
import netzbegruenung.keycloak.app.actiontoken.AppAuthActionToken;
import netzbegruenung.keycloak.app.credentials.AppCredentialData;
import netzbegruenung.keycloak.app.dto.ChallengeConverter;
import netzbegruenung.keycloak.app.jpa.Challenge;
import netzbegruenung.keycloak.app.messaging.MessagingServiceFactory;
import netzbegruenung.keycloak.app.rest.ChallengeResourceProvider;
import netzbegruenung.keycloak.app.rest.StatusResourceProviderFactory;
import org.jboss.logging.Logger;
import org.keycloak.authentication.*;
import org.keycloak.common.util.Base64;
import org.keycloak.common.util.SecretGenerator;
import org.keycloak.common.util.Time;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.credential.CredentialModel;
import org.keycloak.credential.CredentialProvider;
import org.keycloak.device.DeviceRepresentationProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.jpa.entities.ClientEntity;
import org.keycloak.models.jpa.entities.RealmEntity;
import org.keycloak.models.jpa.entities.UserEntity;
import org.keycloak.representations.account.DeviceRepresentation;
import org.keycloak.services.Urls;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.sessions.AuthenticationSessionCompoundId;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.util.JsonSerialization;

import javax.crypto.Cipher;
import jakarta.persistence.EntityManager;
import jakarta.persistence.NoResultException;
import jakarta.persistence.NonUniqueResultException;
import jakarta.persistence.TypedQuery;
import jakarta.ws.rs.core.Response;
import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;

public class AppAuthenticator implements Authenticator, CredentialValidator<AppCredentialProvider> {
	private final Logger logger = Logger.getLogger(AppAuthenticator.class);

	private static final int SECRET_LENGTH = 512 - 11;

	public static final String APP_AUTH_GRANTED_NOTE = "appAuthGranted";

	@Override
	public void authenticate(AuthenticationFlowContext context) {
		CredentialModel appCredentialModel;
		appCredentialModel = getSelectedAppCredential(context);
		if (appCredentialModel == null) return;

		createAppChallenge(context, appCredentialModel);
	}

	private void createAppChallenge(AuthenticationFlowContext context, CredentialModel appCredentialModel) {
		AppCredentialData appCredentialData;
		try {
			appCredentialData = JsonSerialization.readValue(appCredentialModel.getCredentialData(), AppCredentialData.class);
		} catch (IOException e) {
			logger.error("App credential deserialization failed", e);
			Response challenge = context.form()
				.setError("appAuthCriticalError")
				.createForm("app-login.ftl");
			context.challenge(challenge);
			return;
		}
		String secret = SecretGenerator.getInstance().randomString(SECRET_LENGTH, SecretGenerator.ALPHANUM);
		AuthenticationSessionModel authSession = context.getAuthenticationSession();

		Map<String, String> authConfig = context.getAuthenticatorConfig() != null ? context.getAuthenticatorConfig().getConfig() : Collections.emptyMap();

		long tokenExpiration = 60;

		try {
			tokenExpiration = Long.parseLong(authConfig.getOrDefault("appAuthActionTokenExpiration", "60"));
		} catch (NumberFormatException e) {
			logger.warn("Invalid config for app auth action token expiration, falling back to default");
		}

		long expiresAt = Time.currentTime() + tokenExpiration;
		AppAuthActionToken token = new AppAuthActionToken(
			context.getUser().getId(),
			(int) expiresAt,
			AuthenticationSessionCompoundId.fromAuthSession(authSession).getEncodedId(),
			authSession.getClient().getClientId()
		);

		UriBuilder builder = Urls.actionTokenBuilder(
			context.getUriInfo().getBaseUri(),
			token.serialize(context.getSession(), context.getRealm(), context.getUriInfo()),
			authSession.getClient().getClientId(),
			authSession.getTabId(),
			AuthenticationProcessor.getClientData(context.getSession(), authSession)
		);

		DeviceRepresentation deviceRepresentation = context
			.getSession()
			.getProvider(DeviceRepresentationProvider.class)
			.deviceRepresentation();

		try {
			Challenge challenge = upsertAppChallengeEntity(
				context,
				builder.build(context.getRealm().getName()),
				deviceRepresentation,
				appCredentialData.getDeviceId(),
				secret,
				expiresAt
			);

			ChallengeResourceProvider challengeProvider = (ChallengeResourceProvider) context
				.getSession()
				.getProvider(RealmResourceProvider.class, "challenges");

			challengeProvider.notifyListeners(challenge, context.getRealm());

			authSession.setAuthNote("credentialId", appCredentialModel.getId());
			authSession.setAuthNote("secret", secret);
			authSession.setAuthNote("timestamp", String.valueOf(challenge.getUpdatedTimestamp()));

			if (Boolean.parseBoolean(authConfig.getOrDefault("simulation", "false"))) {
				Map<String, String> signatureStringMap = new LinkedHashMap<>();
				signatureStringMap.put("created", authSession.getAuthNote("timestamp"));
				signatureStringMap.put("secret", authSession.getAuthNote("secret"));
				signatureStringMap.put("granted", String.valueOf(true));

				logger.infov("App authentication signature string\n\n{0}\n", AuthenticationUtil.getSignatureString(signatureStringMap));
			}

			MessagingServiceFactory.get(authConfig).send(appCredentialData.getDevicePushId(), ChallengeConverter.getChallengeDto(challenge, context.getSession()));

			Response response = context.form()
				.setAttribute("appAuthStatusUrl", String.format(
					"/realms/%s/%s?%s",
					context.getRealm().getName(),
					StatusResourceProviderFactory.ID,
					context.getRefreshExecutionUrl().getQuery()
				))
				.createForm("app-login.ftl");
			context.challenge(response);
		} catch (NonUniqueResultException e) {
			logger.error("App authentication init failed", e);
			Response challenge = context.form()
				.setError("appAuthCriticalError")
				.createForm("app-login.ftl");
			context.challenge(challenge);
		}
	}

	private Challenge upsertAppChallengeEntity(AuthenticationFlowContext context, URI actionTokenUri, DeviceRepresentation deviceRepresentation, String deviceId, String encryptedSecret, long expiresAt) throws NonUniqueResultException {
		Challenge challenge;
		EntityManager em = getEntityManager(context.getSession());
		RealmEntity realm = em.getReference(RealmEntity.class, context.getRealm().getId());
		UserEntity user = em.getReference(UserEntity.class, context.getUser().getId());
		ClientEntity client = em.getReference(ClientEntity.class, context.getAuthenticationSession().getClient().getId());

		try {
			TypedQuery<Challenge> query = em.createNamedQuery("Challenge.findByRealmAndDeviceId", Challenge.class);
			query.setParameter("realm", realm);
			query.setParameter("deviceId", deviceId);
			challenge = query.getSingleResult();

		} catch (NoResultException e) {
			challenge = new Challenge();
			challenge.setRealm(realm);
			challenge.setDeviceId(deviceId);

		} catch (NonUniqueResultException e) {
			logger.errorf(
				e,
				"Failed to add app authenticator challenge for user [%s] device ID [%s]: duplicate challenge detected",
				context.getUser(),
				deviceId
			);
			throw e;
		}

		challenge.setUser(user);
		challenge.setSecret(encryptedSecret);
		challenge.setTargetUrl(actionTokenUri.toString());
		challenge.setDevice(deviceRepresentation.getDevice());
		challenge.setBrowser(deviceRepresentation.getBrowser());
		challenge.setOs(deviceRepresentation.getOs());
		challenge.setOsVersion(deviceRepresentation.getOsVersion());
		challenge.setIpAddress(deviceRepresentation.getIpAddress());
		challenge.setUpdatedTimestamp(Time.currentTimeMillis());
		challenge.setClient(client);
		challenge.setExpiresAt(expiresAt);

		em.persist(challenge);
		em.flush();

		return challenge;
	}

	private EntityManager getEntityManager(KeycloakSession session) {
		return session.getProvider(JpaConnectionProvider.class).getEntityManager();
	}

	private CredentialModel getSelectedAppCredential(AuthenticationFlowContext context) {
		CredentialModel appCredentialModel;
		AuthenticationSessionModel authSession = context.getAuthenticationSession();
		String credentialId = authSession.getAuthNote("selectedCredentialId");
		authSession.clearAuthNotes();

		if (credentialId == null) {
			List<CredentialModel> appCredentialModels = getCredentialProvider(context.getSession())
				.getAllCredentials(context.getUser());
			if (appCredentialModels.size() > 1) {
				authSession.setAuthNote("appCredentialSelection", "true");
				Response challenge = context.form()
					.setAttribute("appCredentials", appCredentialModels)
					.createForm("app-auth-selection.ftl");
				context.challenge(challenge);
				return null;
			}
			appCredentialModel = appCredentialModels.get(0);
		} else {
			appCredentialModel = getCredentialProvider(context.getSession())
				.getCredentialModel(context.getUser(), credentialId);
		}
		return appCredentialModel;
	}

	private String encryptSecretMessage(AppCredentialData credentialData, String secret) throws GeneralSecurityException, IOException {
		KeyFactory keyFactory = KeyFactory.getInstance(credentialData.getKeyAlgorithm());
		byte[] publicKeyBytes = Base64.decode(credentialData.getPublicKey());
		EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
		PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);

		Cipher encryptCipher = Cipher.getInstance(credentialData.getKeyAlgorithm());
		encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);
		byte[] encryptedMessage = encryptCipher.doFinal(secret.getBytes(StandardCharsets.UTF_8));

		return Base64.encodeBytes(encryptedMessage);
	}

	@Override
	public void action(AuthenticationFlowContext context) {
		final AuthenticationSessionModel authSession = context.getAuthenticationSession();

		if (Boolean.parseBoolean(authSession.getAuthNote("appCredentialSelection"))) {
			authSession.setAuthNote(
				"selectedCredentialId",
				context.getHttpRequest().getDecodedFormParameters().getFirst("app-credential")
			);
			CredentialModel appCredentialModel = getSelectedAppCredential(context);
			createAppChallenge(context, appCredentialModel);
			return;
		}

		final String granted = authSession.getAuthNote(APP_AUTH_GRANTED_NOTE);
		String appAuthStatusUrl = String.format(
			"/realms/%s/%s?%s",
			context.getRealm().getName(),
			StatusResourceProviderFactory.ID,
			context.getRefreshExecutionUrl().getQuery()
		);

		if (granted == null) {
			Response challenge = context.form()
				.setAttribute("appAuthStatusUrl", appAuthStatusUrl)
				.setError("appAuthError")
				.createForm("app-login.ftl");
			context.challenge(challenge);
			return;
		}
		if (!Boolean.parseBoolean(granted)) {
			Response challenge = context.form()
				.setError("appAuthRejected")
				.createForm("app-login.ftl");
			context.challenge(challenge);
			return;
		}
		context.success();
	}

	@Override
	public boolean requiresUser() {
		return true;
	}

	@Override
	public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
		return getCredentialProvider(session).isConfiguredFor(realm, user, getType(session));
	}

	@Override
	public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
		user.addRequiredAction(AppRequiredAction.PROVIDER_ID);
	}

	@Override
	public void close() {

	}

	@Override
	public AppCredentialProvider getCredentialProvider(KeycloakSession session) {
		return (AppCredentialProvider)session.getProvider(CredentialProvider.class, AppCredentialProviderFactory.PROVIDER_ID);
	}

	@Override
	public List<RequiredActionFactory> getRequiredActions(KeycloakSession session) {
		return Collections.singletonList((AppRequiredActionFactory)session.getKeycloakSessionFactory().getProviderFactory(RequiredActionProvider.class, AppRequiredAction.PROVIDER_ID));
	}
}
