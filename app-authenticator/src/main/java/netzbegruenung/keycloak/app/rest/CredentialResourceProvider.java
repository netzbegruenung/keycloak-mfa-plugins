package netzbegruenung.keycloak.app.rest;

import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import netzbegruenung.keycloak.app.AuthenticationUtil;
import netzbegruenung.keycloak.app.credentials.AppCredentialModel;
import netzbegruenung.keycloak.app.dto.TokenDto;
import org.jboss.logging.Logger;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.UserModel;
import org.keycloak.services.resource.RealmResourceProvider;

import java.util.List;
import java.util.Map;

public class CredentialResourceProvider implements RealmResourceProvider {

	private final AppCredentialService appCredentialService;
	private final Logger logger = Logger.getLogger(CredentialResourceProvider.class);

	public final static String INTERNAL_ERROR = "internal_error";


	public CredentialResourceProvider(KeycloakSession session) {
		this.appCredentialService = new AppCredentialService(session);
	}

	@Override
	public Object getResource() {
		return this;
	}

	@PUT
	@Path("registration-token")
	@Consumes(MediaType.APPLICATION_JSON)
	@Produces(MediaType.APPLICATION_JSON)
	public Response updateRegistrationToken(@HeaderParam("Signature") List<String> signatureHeader, TokenDto tokenDto) {
		Map<String, String> signatureMap = AuthenticationUtil.getSignatureMap(signatureHeader);
		if (signatureMap == null) {
			return Response
				.status(Response.Status.BAD_REQUEST)
				.entity(new Message("invalid_request", "Missing, incomplete or invalid signature header"))
				.build();
		}

		String deviceId = signatureMap.get("keyId");
		if (tokenDto == null || tokenDto.token() == null || tokenDto.token().isBlank()) {
			return Response
				.status(Response.Status.BAD_REQUEST)
				.entity(new Message("invalid_request", "Missing token in request body"))
				.build();
		}

		try {
			VerifiedCredentialContainer verifiedCredentialContainer;
			try {
				verifiedCredentialContainer = appCredentialService.getVerifiedCredentialContainer(signatureMap);
			} catch (VerificationErrorResponseException e) {
				return e.getResponse();
			}

			// Update the push token
			AppCredentialModel appCredential = verifiedCredentialContainer.appCredential();
			appCredential.updateDevicePushId(tokenDto.token());
			UserModel user = verifiedCredentialContainer.user();
			user.credentialManager().updateStoredCredential(appCredential);

			return Response.noContent().build();

		} catch (Exception e) {
			logger.error("Failed to update registration token for device ID: " + deviceId, e);
			return Response
				.status(Response.Status.INTERNAL_SERVER_ERROR)
				.entity(new Message(INTERNAL_ERROR, "Internal server error"))
				.build();
		}
	}

	@Override
	public void close() {
	}
}



