package netzbegruenung.keycloak.app.messaging;

import netzbegruenung.keycloak.app.dto.ChallengeDto;

public interface MessagingService {

	void send(String devicePushId, ChallengeDto challenge);
}
