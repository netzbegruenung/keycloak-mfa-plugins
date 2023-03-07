package netzbegruenung.keycloak.app.credentials;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

public class AppCredentialData {
	private final String publicKey;

	@JsonCreator
	public AppCredentialData(@JsonProperty("publicKey") String publicKey) {
		this.publicKey = publicKey;
	}

	public String getPublicKey() {
		return publicKey;
	}
}
