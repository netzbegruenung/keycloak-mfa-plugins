package netzbegruenung.keycloak.app.messaging;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.core.type.TypeReference;
import com.google.firebase.messaging.FirebaseMessaging;
import com.google.firebase.messaging.FirebaseMessagingException;
import com.google.firebase.messaging.Message;
import com.google.firebase.messaging.Notification;
import netzbegruenung.keycloak.app.dto.ChallengeDto;
import org.jboss.logging.Logger;
import org.keycloak.models.KeycloakSession;

import java.io.IOException;
import java.util.Locale;
import java.util.Map;
import java.util.Properties;

public class FcmMessagingService implements MessagingService {

	private final Logger logger = Logger.getLogger(FcmMessagingService.class);

	private final ObjectMapper objectMapper;

	public FcmMessagingService() {
		this.objectMapper = new ObjectMapper();
		objectMapper.setSerializationInclusion(JsonInclude.Include.NON_NULL);
	}

	public void send(String devicePushId, ChallengeDto challenge, KeycloakSession session) {
		if (devicePushId == null) {
			logger.warnf("Skip sending firebase notification: missing device push ID user [%s]", challenge.userName());
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

		Message message = Message.builder()
			.setNotification(Notification.builder()
				.setTitle(localizedMessages.getProperty("appAuthPushTitle", "Anmeldeversuch"))
				.setBody(localizedMessages.getProperty("appAuthPushBody", "Sie haben einen neuen Anmeldeversuch."))
				.build())
			.putAllData(challengeData)
			.setToken(devicePushId)
			.build();

		try {
			String response = FirebaseMessaging.getInstance().send(message);
			logger.debugv("Successfully sent message: %s", response);
		} catch (FirebaseMessagingException e) {
			logger.error("Failed to send firebase app notification", e);
		}
	}

}
