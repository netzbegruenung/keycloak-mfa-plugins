package netzbegruenung.keycloak.app;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.WriterException;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;
import netzbegruenung.keycloak.app.actiontoken.AppActionToken;
import netzbegruenung.keycloak.app.credentials.AppCredentialModel;
import org.jboss.logging.Logger;
import org.keycloak.authentication.CredentialRegistrator;
import org.keycloak.authentication.InitiatedActionSupport;
import org.keycloak.authentication.RequiredActionContext;
import org.keycloak.authentication.RequiredActionProvider;
import org.keycloak.common.util.Base64;
import org.keycloak.common.util.Time;
import org.keycloak.services.Urls;
import org.keycloak.sessions.AuthenticationSessionCompoundId;
import org.keycloak.sessions.AuthenticationSessionModel;

import javax.ws.rs.core.Response;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URI;

public class AppRequiredAction implements RequiredActionProvider, CredentialRegistrator {

	private static final Logger logger = Logger.getLogger(AppRequiredAction.class);

	public static String PROVIDER_ID = "app-register";

	@Override
	public InitiatedActionSupport initiatedActionSupport() {
		return InitiatedActionSupport.SUPPORTED;
	}

	@Override
	public void evaluateTriggers(RequiredActionContext requiredActionContext) {

	}

	@Override
	public void requiredActionChallenge(RequiredActionContext context) {
		String qrCode = createActionToken(context);
		Response challenge = context.form()
			.setAttribute("appAuthQrCode", qrCode)
			.createForm("app-auth-setup.ftl");
		context.challenge(challenge);
	}

	private String createActionToken(RequiredActionContext context) {
		int validityInSecs = context.getRealm().getActionTokenGeneratedByUserLifespan();
		int absoluteExpirationInSecs = Time.currentTime() + validityInSecs;
		final AuthenticationSessionModel authSession = context.getAuthenticationSession();
		final String clientId = authSession.getClient().getClientId();
		String authSessionEncodedId = AuthenticationSessionCompoundId.fromAuthSession(authSession).getEncodedId();

		String token = new AppActionToken(
			context.getUser().getId(),
			absoluteExpirationInSecs,
			authSessionEncodedId,
			clientId
		).serialize(
			context.getSession(),
			context.getRealm(),
			context.getUriInfo()
		);

		URI submitActionTokenUrl = Urls
			.actionTokenBuilder(context.getUriInfo().getBaseUri(), token, clientId, authSession.getTabId())
			.build(context.getRealm().getName());

		logger.infov("Action token URI: {0}", submitActionTokenUrl);

		return createQrCode(submitActionTokenUrl.toString());
	}

	private String createQrCode(String uri) {
		try {
			int width = 512;
			int height = 512;

			QRCodeWriter writer = new QRCodeWriter();
			final BitMatrix bitMatrix = writer.encode(uri, BarcodeFormat.QR_CODE, width, height);

			ByteArrayOutputStream bos = new ByteArrayOutputStream();
			MatrixToImageWriter.writeToStream(bitMatrix, "png", bos);
			bos.close();

			return Base64.encodeBytes(bos.toByteArray());
		} catch (WriterException | IOException e) {
			throw new RuntimeException(e);
		}
	}

	@Override
	public void processAction(RequiredActionContext context) {
		final AuthenticationSessionModel authSession = context.getAuthenticationSession();
		if (!Boolean.parseBoolean(authSession.getAuthNote("appSetupSuccessful"))) {
			String qrCode = createActionToken(context);
			Response challenge = context.form()
				.setAttribute("appAuthQrCode", qrCode)
				.setError("appAuthSetupError")
				.createForm("app-auth-setup.ftl");
			context.challenge(challenge);
			return;
		}
		context.success();
	}

	@Override
	public void close() {

	}
}
