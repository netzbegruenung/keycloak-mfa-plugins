package netzbegruenung.keycloak.app.dto;

import netzbegruenung.keycloak.app.jpa.Challenge;
import org.keycloak.models.KeycloakSession;
import org.keycloak.services.util.ResolveRelative;

public class ChallengeConverter {
	public static ChallengeDto getChallengeDto(Challenge challenge, KeycloakSession session) {
		return new ChallengeDto(
			challenge.getUser().getUsername(),
			challenge.getUser().getFirstName(),
			challenge.getUser().getLastName(),
			challenge.getTargetUrl(),
			challenge.getSecret(),
			challenge.getUpdatedTimestamp(),
			challenge.getIpAddress(),
			challenge.getDevice(),
			challenge.getBrowser(),
			challenge.getOs(),
			challenge.getOsVersion(),
			// replaced broken property resolver intentionally for something simpler
			// https://github.com/keycloak/keycloak/pull/36472
			challenge.getClient().getName().equals("${client_account-console}") ? "Accountkonsole" : challenge.getClient().getName(),
			ResolveRelative.resolveRelativeUri(session, challenge.getClient().getRootUrl(), challenge.getClient().getBaseUrl())
		);
	}
}
