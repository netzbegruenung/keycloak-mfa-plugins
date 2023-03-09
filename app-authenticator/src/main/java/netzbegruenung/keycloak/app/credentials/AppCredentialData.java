package netzbegruenung.keycloak.app.credentials;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

public class AppCredentialData {
	private final String publicKey;

	private final String devicedId;
	private final String deviceOs;

	@JsonCreator
	public AppCredentialData(
		@JsonProperty("publicKey") String publicKey,
		@JsonProperty("deviceId") String devicedId,
		@JsonProperty("deviceOs") String deviceOs
	) {
		this.publicKey = publicKey;
		this.devicedId = devicedId;
		this.deviceOs = deviceOs;
	}

	public String getPublicKey() {
		return publicKey;
	}

	public String getDevicedId() {
		return devicedId;
	}

	public String getDeviceOs() {
		return deviceOs;
	}
}
