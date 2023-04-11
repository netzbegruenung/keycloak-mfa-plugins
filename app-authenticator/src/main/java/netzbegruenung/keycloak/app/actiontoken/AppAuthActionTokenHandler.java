package netzbegruenung.keycloak.app.actiontoken;

import netzbegruenung.keycloak.app.AppCredentialProvider;
import netzbegruenung.keycloak.app.AppCredentialProviderFactory;
import netzbegruenung.keycloak.app.credentials.AppCredentialData;
import org.apache.commons.codec.binary.Base64;
import org.jboss.logging.Logger;
import org.keycloak.authentication.actiontoken.AbstractActionTokenHandler;
import org.keycloak.authentication.actiontoken.ActionTokenContext;
import org.keycloak.credential.CredentialModel;
import org.keycloak.credential.CredentialProvider;
import org.keycloak.events.Errors;
import org.keycloak.events.EventType;
import org.keycloak.services.messages.Messages;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.util.JsonSerialization;

import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import java.io.IOException;
import java.security.*;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

public class AppAuthActionTokenHandler extends AbstractActionTokenHandler<AppAuthActionToken> {

	private final Logger logger = Logger.getLogger(AppAuthActionTokenHandler.class);

	public AppAuthActionTokenHandler() {
		super(
			AppAuthActionToken.TOKEN_TYPE,
			AppAuthActionToken.class,
			Messages.INVALID_REQUEST,
			EventType.EXECUTE_ACTION_TOKEN,
			Errors.INVALID_REQUEST
		);
	}

	@Override
	public Response handleToken(AppAuthActionToken token, ActionTokenContext<AppAuthActionToken> tokenContext) {
		MultivaluedMap<String, String> queryParameters = tokenContext.getRequest().getUri().getQueryParameters();
		String signature = queryParameters.getFirst("signature");
		String algorithm = queryParameters.getFirst("algorithm");
		String granted = queryParameters.getFirst("granted");

		if (signature == null || algorithm == null || granted == null) {
			return Response.status(Response.Status.BAD_REQUEST).build();
		}

		AuthenticationSessionModel authSession = ActionTokenUtil.getOriginalAuthSession(
			tokenContext.getSession(),
			tokenContext.getRealm(),
			token.getOriginalAuthenticationSessionId()
		);

		AppCredentialProvider appCredentialProvider = (AppCredentialProvider) tokenContext
			.getSession()
			.getProvider(CredentialProvider.class, AppCredentialProviderFactory.PROVIDER_ID);
		CredentialModel appCredentialModel = appCredentialProvider
			.getCredentialModel(authSession.getAuthenticatedUser(), authSession.getAuthNote("credentialId"));

		try {
			AppCredentialData appCredentialData = JsonSerialization.readValue(appCredentialModel.getCredentialData(), AppCredentialData.class);

			KeyFactory keyFactory = KeyFactory.getInstance(appCredentialData.getAlgorithm());
			byte[] publicKeyBytes = Base64.decodeBase64(appCredentialData.getPublicKey());
			EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
			PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);

			Signature sign = Signature.getInstance(algorithm);
			sign.initVerify(publicKey);
			sign.update(authSession.getAuthNote("secret").getBytes());

			if (!sign.verify(Base64.decodeBase64(signature))) {
				logger.errorv("App auth: invalid signature for user: {0}", authSession.getAuthenticatedUser().getUsername());
				return Response.status(Response.Status.FORBIDDEN).build();
			}
			if (!Boolean.parseBoolean(granted)) {
				authSession.setAuthNote("appAuthGranted", Boolean.toString(false));
				return Response.status(Response.Status.NO_CONTENT).build();
			}
		} catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException | SignatureException | InvalidKeyException e) {
			logger.errorf(
				e,
				"App auth: signature verification failed for user: [%s], probably due to malformed signature or wrong algorithm",
				authSession.getAuthenticatedUser().getUsername()
			);
			return Response.status(Response.Status.INTERNAL_SERVER_ERROR).type(MediaType.TEXT_PLAIN_TYPE).build();
		}

		authSession.setAuthNote("appAuthGranted", Boolean.toString(true));
		return Response.status(Response.Status.NO_CONTENT).build();
	}

	@Override
	public boolean canUseTokenRepeatedly(AppAuthActionToken token, ActionTokenContext<AppAuthActionToken> tokenContext) {
		return false;
	}
}
