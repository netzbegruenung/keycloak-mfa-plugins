package netzbegruenung.keycloak.app.messaging;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.core.type.TypeReference;
import com.google.auth.oauth2.GoogleCredentials;
import com.google.auth.oauth2.ServiceAccountCredentials;
import netzbegruenung.keycloak.app.dto.ChallengeDto;
import org.jboss.logging.Logger;
import org.keycloak.models.KeycloakSession;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Collections;
import java.util.Locale;
import java.util.Map;
import java.util.Properties;

public class FcmMessagingService implements MessagingService {

	private static final String FCM_SEND_ENDPOINT = "/v1/projects/%s/messages:send";
	private static final String BASE_URL = "https://fcm.googleapis.com";

	private final Logger logger = Logger.getLogger(FcmMessagingService.class);

	private final ObjectMapper objectMapper;

	private final String projectId;

	private final GoogleCredentials credentials;

	private final HttpClient httpClient;

	public FcmMessagingService() {
		this.objectMapper = new ObjectMapper();
		objectMapper.setSerializationInclusion(JsonInclude.Include.NON_NULL);
		this.httpClient = HttpClient.newHttpClient();
		try {
			this.credentials = GoogleCredentials.getApplicationDefault()
				.createScoped(Collections.singleton("https://www.googleapis.com/auth/firebase.messaging"));
			this.projectId = ((ServiceAccountCredentials) this.credentials).getProjectId();
		} catch (IOException e) {
			logger.error("Failed to initialize GoogleCredentials from application default credentials", e);
			throw new RuntimeException("Failed to initialize GoogleCredentials", e);
		}
	}

	public void send(String devicePushId, ChallengeDto challenge, KeycloakSession session) {
		if (devicePushId == null || devicePushId.isEmpty()) {
			logger.warnf("Skip sending firebase notification: missing device push ID user [%s]", challenge.userName());
			return;
		}
		if (projectId == null) {
			logger.error("Firebase Project ID is not configured. Cannot send push notification.");
			return;
		}
		Map<String, String> challengeData = objectMapper.convertValue(challenge, new TypeReference<>() {});
		Properties localizedMessages;
		try {
			localizedMessages = session.theme()
				.getTheme(org.keycloak.theme.Theme.Type.LOGIN)
				.getMessages(Locale.GERMAN);
		} catch (IOException e) {
			logger.warn("Failed to load translations, falling back to default messages.", e);
			localizedMessages = new Properties();
		}

		try {
			String message = buildFcmV1Message(
				devicePushId,
				localizedMessages.getProperty("appAuthPushTitle", "Anmeldeversuch"),
				localizedMessages.getProperty("appAuthPushBody", "Sie haben einen neuen Anmeldeversuch."),
				challengeData
			);

			HttpRequest request = HttpRequest.newBuilder()
				.uri(new URI(BASE_URL + String.format(FCM_SEND_ENDPOINT, projectId)))
				.header("Authorization", "Bearer " + getServiceAccountAccessToken())
				.header("Content-Type", "application/json; UTF-8")
				.POST(HttpRequest.BodyPublishers.ofString(message))
				.build();

			HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

			if (response.statusCode() == 200) {
				logger.debugv("Successfully sent message: %s", response.body());
			} else {
				logger.errorf("Failed to send firebase app notification. Status: %s, Response: %s", response.statusCode(), response.body());
			}

		} catch (Exception e) {
			logger.error("Failed to send firebase app notification", e);
		}
	}

	private String buildFcmV1Message(String token, String title, String body, Map<String, String> data) throws IOException {
		Map<String, Object> notification = Map.of("title", title, "body", body);
		Map<String, Object> message = Map.of(
			"token", token,
			"notification", notification,
			"data", data
		);
		return objectMapper.writeValueAsString(Map.of("message", message));
	}

	private String getServiceAccountAccessToken() throws IOException {
		credentials.refreshIfExpired();
		return credentials.getAccessToken().getTokenValue();
	}
}
