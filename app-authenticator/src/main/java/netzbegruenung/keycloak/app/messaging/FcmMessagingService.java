package netzbegruenung.keycloak.app.messaging;

import com.google.firebase.messaging.FirebaseMessaging;
import com.google.firebase.messaging.FirebaseMessagingException;
import com.google.firebase.messaging.Message;
import org.jboss.logging.Logger;

import java.net.URI;

public class FcmMessagingService implements MessagingService {

	private final Logger logger = Logger.getLogger(FcmMessagingService.class);

	public void send(String registrationToken, String challenge, URI targetUrl) {
		Message message = Message.builder()
			.putData("challenge", challenge)
			.putData("targetUrl", targetUrl.toString())
			.setToken(registrationToken)
			.build();

		try {
			String response = FirebaseMessaging.getInstance().send(message);
			logger.debugv("Successfully sent message: ", response);
		} catch (FirebaseMessagingException e) {
			throw new RuntimeException(e);
		}
	}

}
