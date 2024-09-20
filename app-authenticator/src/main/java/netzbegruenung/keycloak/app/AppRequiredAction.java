package netzbegruenung.keycloak.app;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.WriterException;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;
import netzbegruenung.keycloak.app.actiontoken.ActionTokenUtil;
import netzbegruenung.keycloak.app.actiontoken.AppSetupActionToken;
import netzbegruenung.keycloak.app.credentials.AppCredentialModel;
import netzbegruenung.keycloak.app.rest.StatusResourceProviderFactory;
import org.jboss.logging.Logger;
import org.keycloak.authentication.CredentialRegistrator;
import org.keycloak.authentication.InitiatedActionSupport;
import org.keycloak.authentication.RequiredActionContext;
import org.keycloak.authentication.RequiredActionProvider;
import org.keycloak.common.util.Base64;
import org.keycloak.models.KeycloakSession;
import org.keycloak.sessions.AuthenticationSessionModel;

import jakarta.ws.rs.core.Response;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URI;

public class AppRequiredAction implements RequiredActionProvider, CredentialRegistrator {

	public static final String PROVIDER_ID = "app-register";

	@Override
	public InitiatedActionSupport initiatedActionSupport() {
		return InitiatedActionSupport.SUPPORTED;
	}

	@Override
	public void evaluateTriggers(RequiredActionContext requiredActionContext) {

	}

	@Override
	public void requiredActionChallenge(RequiredActionContext context) {
		URI actionTokenUrl = ActionTokenUtil.createActionToken(
			AppSetupActionToken.class,
			context.getAuthenticationSession(),
			context.getSession(),
			context.getRealm(),
			context.getUser(),
			context.getUriInfo()
		);

		Response challenge = context.form()
			.setAttribute("appAuthQrCode", createQrCode(actionTokenUrl.toString()))
			.setAttribute("appAuthActionTokenUrl", actionTokenUrl.toString())
			.setAttribute("appAuthStatusUrl", String.format(
				"/realms/%s/%s?%s",
				context.getRealm().getName(),
				StatusResourceProviderFactory.ID,
				context.getActionUrl().getQuery()
			))
			.createForm("app-auth-setup.ftl");
		context.challenge(challenge);
	}

	private String createQrCode(String uri) {
		try {
			int width = 400;
			int height = 400;

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
			URI actionTokenUrl = ActionTokenUtil.createActionToken(
				AppSetupActionToken.class,
				context.getAuthenticationSession(),
				context.getSession(),
				context.getRealm(),
				context.getUser(),
				context.getUriInfo()
			);

			String errorMessage = Boolean.parseBoolean(authSession.getAuthNote("duplicateDeviceId")) ? "appAuthSetupDuplicate" : "appAuthSetupError";

			Response challenge = context.form()
				.setAttribute("appAuthQrCode", createQrCode(actionTokenUrl.toString()))
				.setAttribute("appAuthActionTokenUrl", actionTokenUrl.toString())
				.setAttribute("appAuthStatusUrl", String.format(
					"/realms/%s/%s?%s",
					context.getRealm().getName(),
					StatusResourceProviderFactory.ID,
					context.getActionUrl().getQuery()
				))
				.setError(errorMessage)
				.createForm("app-auth-setup.ftl");
			context.challenge(challenge);
			return;
		}
		context.success();
	}

	@Override
	public void close() {

	}

	@Override
	public String getCredentialType(KeycloakSession keycloakSession, AuthenticationSessionModel authenticationSessionModel) {
		return AppCredentialModel.TYPE;
	}
}
