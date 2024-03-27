package netzbegruenung.keycloak.app.messaging;

import org.jboss.logging.Logger;

import java.util.Map;

public class MessagingServiceFactory {

	private static final Logger logger = Logger.getLogger(MessagingServiceFactory.class);

	public static MessagingService get(Map<String, String> config) {
		if (Boolean.parseBoolean(config.getOrDefault("simulation", "false"))) {
			return (devicePushId, challengeDto) ->
				logger.infov(
					"Simulation mode - send authentication request: action Url {0}, challenge {1}, device push ID {2}, user {3}",
					challengeDto.getTargetUrl(),
					challengeDto.getCodeChallenge(),
					devicePushId,
					challengeDto.getUserName()
				);
		} else {
			return new FcmMessagingService();
		}
	}
}
