package netzbegruenung.keycloak.app.messaging;

import org.jboss.logging.Logger;

import java.util.Map;

public class MessagingServiceFactory {

	private static final Logger logger = Logger.getLogger(MessagingServiceFactory.class);

	private static MessagingService fcmMessagingService;
	private static boolean isInitialized = false;

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
			initialize();
			if (fcmMessagingService != null) {
				return fcmMessagingService;
			} else {
				return (devicePushId, challengeDto, session) ->
					logger.error("Firebase not initialized, cannot send push notification. Check previous logs for details.");
			}
		}
	}

	private static synchronized void initialize() {
		if (isInitialized) {
			return;
		}
		try {
			fcmMessagingService = new FcmMessagingService();
			logger.info("Messaging service initialized successfully");
		} catch (Exception e) {
			logger.error("Failed to initialize messaging service. The App Authenticator will not be able to send push notifications. Please make sure the GOOGLE_APPLICATION_CREDENTIALS environment variable is set correctly.", e);
		} finally {
			isInitialized = true;
		}
	}
}
