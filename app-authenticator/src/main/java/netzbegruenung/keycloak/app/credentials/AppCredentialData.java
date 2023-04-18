package netzbegruenung.keycloak.app.credentials;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

public class AppCredentialData {
	private final String publicKey;

	private final String deviceId;
	private final String deviceOs;

	private final String keyAlgorithm;

	private final String signatureAlgorithm;

	private final String registrationToken;


	@JsonCreator
	public AppCredentialData(
		@JsonProperty("publicKey") String publicKey,
		@JsonProperty("deviceId") String deviceId,
		@JsonProperty("deviceOs") String deviceOs,
		@JsonProperty("keyAlgorithm") String keyAlgorithm,
		@JsonProperty("signatureAlgorithm") String signatureAlgorithm,
		@JsonProperty("registrationToken") String registrationToken
	) {
		this.publicKey = publicKey;
		this.deviceId = deviceId;
		this.deviceOs = deviceOs;
		this.keyAlgorithm = keyAlgorithm;
		this.signatureAlgorithm = signatureAlgorithm;
		this.registrationToken = registrationToken;
	}

	public String getPublicKey() {
		return publicKey;
	}

	public String getDeviceId() {
		return deviceId;
	}

	public String getDeviceOs() {
		return deviceOs;
	}

	public String getKeyAlgorithm() {
		return keyAlgorithm;
	}

	public String getRegistrationToken() {
		return registrationToken;
	}

	public String getSignatureAlgorithm() {
		return signatureAlgorithm;
	}
}
