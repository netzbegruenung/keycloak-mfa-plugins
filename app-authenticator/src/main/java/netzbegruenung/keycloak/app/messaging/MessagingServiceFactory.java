package netzbegruenung.keycloak.app.messaging;

import org.jboss.logging.Logger;

import java.util.Map;

public class MessagingServiceFactory {

	private static final Logger logger = Logger.getLogger(MessagingServiceFactory.class);

	public static MessagingService get(Map<String, String> config) {
		if (Boolean.parseBoolean(config.getOrDefault("simulation", "false"))) {
			return (deviceId, challenge, actionUrl) ->
				logger.infov("Send authentication request: action Url {0}, challenge {1}, device ID {2}", actionUrl, challenge, deviceId);
		} else {
			return new FcmMessagingService();
		}
	}
}
