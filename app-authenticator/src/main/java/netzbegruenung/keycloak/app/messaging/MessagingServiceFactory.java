package netzbegruenung.keycloak.app.messaging;

import com.google.auth.oauth2.GoogleCredentials;
import com.google.firebase.FirebaseApp;
import com.google.firebase.FirebaseOptions;
import org.jboss.logging.Logger;

import java.io.IOException;
import java.util.Map;

public class MessagingServiceFactory {

	private static final Logger logger = Logger.getLogger(MessagingServiceFactory.class);

	private static boolean isFirebaseInitialized = false;

	public static MessagingService get(Map<String, String> config) {
		if (Boolean.parseBoolean(config.getOrDefault("simulation", "false"))) {
			return (devicePushId, challengeDto, session) ->
				logger.infov(
					"Simulation mode - send authentication request: action Url {0}, challenge {1}, device push ID {2}, user {3}",
					challengeDto.targetUrl(),
					challengeDto.codeChallenge(),
					devicePushId,
					challengeDto.userName()
				);
		} else {
			initializeFirebase();
			if (isFirebaseInitialized) {
				return new FcmMessagingService();
			} else {
				return (devicePushId, challengeDto, session) ->
					logger.error("Firebase not initialized, cannot send push notification. Check previous logs for details.");
			}
		}
	}

	private static synchronized void initializeFirebase() {
		if (isFirebaseInitialized) {
			return;
		}

		try {
			FirebaseOptions options = FirebaseOptions.builder()
				.setCredentials(GoogleCredentials.getApplicationDefault())
				.build();
			FirebaseApp.initializeApp(options);
			isFirebaseInitialized = true;
			logger.info("Firebase Cloud Messaging initialized successfully");
		} catch (IOException e) {
			logger.error("Failed to initialize Firebase. The App Authenticator will not be able to send push notifications. Please make sure the GOOGLE_APPLICATION_CREDENTIALS environment variable is set correctly and points to a valid service account credentials file.", e);
		}
	}
}
