package netzbegruenung.keycloak.app.credentials;

import org.keycloak.common.util.Time;
import org.keycloak.credential.CredentialModel;
import org.keycloak.util.JsonSerialization;

import java.io.IOException;

public class AppCredentialModel extends CredentialModel {

	public static final String TYPE = "APP_CREDENTIAL";

	private final AppCredentialData credentialData;

	private AppCredentialModel(AppCredentialData credentialData) {
		this.credentialData = credentialData;
	}

	private AppCredentialModel(String publicKey, String deviceId, String deviceOs, String keyAlgorithm, String signatureAlgorithm, String devicePushId) {
		credentialData = new AppCredentialData(publicKey, deviceId, deviceOs, keyAlgorithm, signatureAlgorithm, devicePushId);
	}

	public static AppCredentialModel createFromCredentialModel(CredentialModel credentialModel) {
		try {
			AppCredentialData credentialData = JsonSerialization.readValue(credentialModel.getCredentialData(), AppCredentialData.class);

			AppCredentialModel appCredentialModel = new AppCredentialModel(credentialData);
			appCredentialModel.setUserLabel(credentialModel.getUserLabel());
			appCredentialModel.setCreatedDate(credentialModel.getCreatedDate());
			appCredentialModel.setType(TYPE);
			appCredentialModel.setId(credentialModel.getId());
			appCredentialModel.setCredentialData(credentialModel.getCredentialData());
			appCredentialModel.setUserLabel(credentialData.getDeviceOs());
			return appCredentialModel;
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}

	public static AppCredentialModel createAppCredential(String publicKey, String deviceId, String deviceOs, String keyAlgorithm, String signatureAlgorithm, String devicePushId) {
		AppCredentialModel appCredentialModel = new AppCredentialModel(publicKey, deviceId, deviceOs, keyAlgorithm, signatureAlgorithm, devicePushId);
		appCredentialModel.fillCredentialModelFields();
		return appCredentialModel;
	}

	private void fillCredentialModelFields() {
		try {
			setCredentialData(JsonSerialization.writeValueAsString(credentialData));
			setType(TYPE);
			setCreatedDate(Time.currentTimeMillis());
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}

	public AppCredentialData getAppCredentialData() {
		return credentialData;
	}
}
