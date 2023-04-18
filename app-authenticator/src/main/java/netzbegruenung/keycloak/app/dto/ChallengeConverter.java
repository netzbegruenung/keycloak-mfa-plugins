package netzbegruenung.keycloak.app.dto;

import netzbegruenung.keycloak.app.jpa.Challenge;

public class ChallengeConverter {
	public static ChallengeDto getChallengeDto(Challenge challenge) {
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
			challenge.getOsVersion()
		);
	}
}
