package netzbegruenung.keycloak.app.dto;

import java.io.Serializable;

/**
 * A DTO for the {@link netzbegruenung.keycloak.app.jpa.Challenge} entity
 */
public record ChallengeDto(String userName, String userFirstName, String userLastName, String targetUrl,
						   String codeChallenge, Long updatedTimestamp, String ipAddress, String device, String browser,
						   String os, String osVersion, String clientName, String clientUrl, String loginId) implements Serializable {
}
