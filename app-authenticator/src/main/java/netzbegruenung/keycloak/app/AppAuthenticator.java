package netzbegruenung.keycloak.app;

import netzbegruenung.keycloak.app.actiontoken.ActionTokenUtil;
import netzbegruenung.keycloak.app.actiontoken.AppAuthActionToken;
import netzbegruenung.keycloak.app.credentials.AppCredentialData;
import netzbegruenung.keycloak.app.messaging.MessagingServiceFactory;
import org.apache.commons.codec.binary.Base64;
import org.jboss.logging.Logger;
import org.jetbrains.annotations.Nullable;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.CredentialValidator;
import org.keycloak.common.util.SecretGenerator;
import org.keycloak.credential.CredentialModel;
import org.keycloak.credential.CredentialProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.util.JsonSerialization;

import javax.crypto.Cipher;
import javax.ws.rs.core.Response;
import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Collections;
import java.util.List;
import java.util.Map;

public class AppAuthenticator implements Authenticator, CredentialValidator<AppCredentialProvider> {
	private final Logger logger = Logger.getLogger(AppAuthenticator.class);

	private static final int SECRET_LENGTH = 512 - 11;

	@Override
	public void authenticate(AuthenticationFlowContext context) {
		CredentialModel appCredentialModel;
		appCredentialModel = getSelectedAppCredential(context);
		if (appCredentialModel == null) return;

		createAppChallenge(context, appCredentialModel);
	}

	private void createAppChallenge(AuthenticationFlowContext context, CredentialModel appCredentialModel) {
		try {
			AppCredentialData appCredentialData = JsonSerialization.readValue(appCredentialModel.getCredentialData(), AppCredentialData.class);
			String secret = SecretGenerator.getInstance().randomString(SECRET_LENGTH, SecretGenerator.ALPHANUM);
			context.getAuthenticationSession().setAuthNote("secret", secret);
			context.getAuthenticationSession().setAuthNote("credentialId", appCredentialModel.getId());

			String encryptedSecret = encryptSecretMessage(appCredentialData, secret);

			URI actionTokenUri = ActionTokenUtil.createActionToken(
				AppAuthActionToken.class,
				context.getAuthenticationSession(),
				context.getSession(),
				context.getRealm(),
				context.getUser(),
				context.getUriInfo()
			);

			Map<String, String> authConfig = context.getAuthenticatorConfig() != null ? context.getAuthenticatorConfig().getConfig() : Collections.emptyMap();
			if (Boolean.parseBoolean(authConfig.getOrDefault("simulation", "false"))) {
				logger.infov("App authentication secret {0}", secret);
			}
			MessagingServiceFactory.get(authConfig).send(
				appCredentialData.getDevicedId(),
				encryptedSecret,
				actionTokenUri
			);

			Response challenge = context.form()
				.createForm("app-login.ftl");
			context.challenge(challenge);
		} catch (IOException | GeneralSecurityException e) {
			logger.error("App authentication init failed", e);
			Response challenge = context.form()
				.setError("appAuthError")
				.createForm("app-login.ftl");
			context.challenge(challenge);
		}
	}

	@Nullable
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

	private String encryptSecretMessage(AppCredentialData credentialData, String secret) throws GeneralSecurityException {
		KeyFactory keyFactory = KeyFactory.getInstance(credentialData.getAlgorithm());
		byte[] publicKeyBytes = Base64.decodeBase64(credentialData.getPublicKey());
		EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
		PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);

		Cipher encryptCipher = Cipher.getInstance(credentialData.getAlgorithm());
		encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);
		byte[] encryptedMessage = encryptCipher.doFinal(secret.getBytes(StandardCharsets.UTF_8));

		return Base64.encodeBase64String(encryptedMessage);
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

		final String granted = authSession.getAuthNote("appAuthGranted");
		if (granted == null) {
			Response challenge = context.form()
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
		return false;
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
}
