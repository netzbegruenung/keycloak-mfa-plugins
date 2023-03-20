package netzbegruenung.keycloak.app.messaging;

import java.net.URI;

public interface MessagingService {

	void send(String deviceId, String challenge, URI targetUrl);
}
