package netzbegruenung.keycloak.app.messaging;

import netzbegruenung.keycloak.app.dto.ChallengeDto;
import org.keycloak.models.KeycloakSession;

public interface MessagingService {

	void send(String devicePushId, ChallengeDto challenge, KeycloakSession session);
}
