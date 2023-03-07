package netzbegruenung.keycloak.app.credentials;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

public class AppSecretData {
	private final String deviceId;

	@JsonCreator
	public AppSecretData(@JsonProperty("deviceId") String deviceId) {
		this.deviceId = deviceId;
	}

	public String getDeviceId() {
		return deviceId;
	}
}
