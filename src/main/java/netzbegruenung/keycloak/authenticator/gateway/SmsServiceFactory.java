package netzbegruenung.keycloak.authenticator.gateway;

import netzbegruenung.keycloak.authenticator.gateway.ApiSmsService;
import org.jboss.logging.Logger;

import java.util.Map;

/**
 * @author Netzbegrünung e.V.
 */
public class SmsServiceFactory {

	private static final Logger LOG = Logger.getLogger(SmsServiceFactory.class);

	public static SmsService get(Map<String, String> config) {
		if (Boolean.parseBoolean(config.getOrDefault("simulation", "false"))) {
			return (phoneNumber, message) ->
				LOG.warn(String.format("***** SIMULATION MODE ***** Would send SMS to %s with text: %s", phoneNumber, message));
		} else {
			LOG.warn(String.format("***** SIMULATION MODE ***** Would send SMS to %s with text: %s", phoneNumber, message));
		}
	}

}
