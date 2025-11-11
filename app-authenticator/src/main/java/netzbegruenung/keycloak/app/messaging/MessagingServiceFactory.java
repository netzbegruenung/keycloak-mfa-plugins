package netzbegruenung.keycloak.app.messaging;

import com.google.auth.oauth2.GoogleCredentials;
import com.google.firebase.FirebaseApp;
import com.google.firebase.FirebaseOptions;
import org.jboss.logging.Logger;

import java.io.FileInputStream;
import java.io.IOException;
import java.util.Map;

public class MessagingServiceFactory {

	private static final Logger logger = Logger.getLogger(MessagingServiceFactory.class);

	private static boolean isFirebaseInitialized = false;

	public static MessagingService get(Map<String, String> config) {
		if (Boolean.parseBoolean(config.getOrDefault("simulation", "false"))) {
			return (devicePushId, challengeDto) ->
				logger.infov(
					"Simulation mode - send authentication request: action Url {0}, challenge {1}, device push ID {2}, user {3}",
					challengeDto.targetUrl(),
					challengeDto.codeChallenge(),
					devicePushId,
					challengeDto.userName()
				);
		} else {
			initializeFirebase(config);
			return new FcmMessagingService();
		}
	}

	private static synchronized void initializeFirebase(Map<String, String> config) {
		if (isFirebaseInitialized) {
			return;
		}

		String serviceAccountFile = config.get("fcmServiceAccountFile");
		if (serviceAccountFile == null || serviceAccountFile.isEmpty()) {
			logger.error("FCM Service Account File not configured. Please set 'fcmServiceAccountFile' in the authenticator config.");
			return;
		}

		try (FileInputStream serviceAccount = new FileInputStream(serviceAccountFile)) {
			FirebaseOptions options = FirebaseOptions.builder()
				.setCredentials(GoogleCredentials.fromStream(serviceAccount))
				.build();
			FirebaseApp.initializeApp(options);
			isFirebaseInitialized = true;
			logger.info("Firebase Cloud Messaging initialized successfully");

		} catch (IOException e) {
			logger.error("Failed to initialize Firebase Cloud Messaging", e);
		}
	}
}
