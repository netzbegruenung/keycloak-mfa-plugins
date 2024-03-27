package netzbegruenung.keycloak.app.messaging;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.firebase.messaging.FirebaseMessaging;
import com.google.firebase.messaging.FirebaseMessagingException;
import com.google.firebase.messaging.Message;
import netzbegruenung.keycloak.app.dto.ChallengeDto;
import org.jboss.logging.Logger;

import java.net.URI;
import java.util.Map;

public class FcmMessagingService implements MessagingService {

	private final Logger logger = Logger.getLogger(FcmMessagingService.class);

	private final ObjectMapper objectMapper = new ObjectMapper();

	public void send(String devicePushId, ChallengeDto challenge) {
		if (devicePushId == null) {
			logger.infof("Skip sending firebase notification: missing device push ID user [%s]", challenge.getUserName());
			return;
		}
		Map<String, String> challengeMap = objectMapper.convertValue(challenge, Map.class);
		Message message = Message.builder()
			.putAllData(challengeMap)
			.setToken(devicePushId)
			.build();

		try {
			String response = FirebaseMessaging.getInstance().send(message);
			logger.debugv("Successfully sent message: ", response);
		} catch (FirebaseMessagingException e) {
			logger.error("Failed to send firebase app notification", e);
		}
	}

}
