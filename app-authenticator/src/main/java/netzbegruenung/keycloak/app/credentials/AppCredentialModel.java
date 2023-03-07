package netzbegruenung.keycloak.app.credentials;

import org.keycloak.common.util.Time;
import org.keycloak.credential.CredentialModel;
import org.keycloak.util.JsonSerialization;

import java.io.IOException;

public class AppCredentialModel extends CredentialModel {

	public static final String TYPE = "APP_CREDENTIAL";

	private final AppCredentialData credentialData;

	private final AppSecretData secretData;

	private AppCredentialModel(AppCredentialData credentialData, AppSecretData secretData) {
		this.credentialData = credentialData;
		this.secretData = secretData;
	}

	private AppCredentialModel(String deviceId, String publicKey) {
		credentialData = new AppCredentialData(publicKey);
		secretData = new AppSecretData(deviceId);
	}

	public static AppCredentialModel createFromCredentialModel(CredentialModel credentialModel) {
		try {
			AppCredentialData credentialData = JsonSerialization.readValue(credentialModel.getCredentialData(), AppCredentialData.class);
			AppSecretData secretData = JsonSerialization.readValue(credentialModel.getSecretData(), AppSecretData.class);

			AppCredentialModel appCredentialModel = new AppCredentialModel(credentialData, secretData);
			appCredentialModel.setUserLabel(credentialModel.getUserLabel());
			appCredentialModel.setCreatedDate(credentialModel.getCreatedDate());
			appCredentialModel.setType(TYPE);
			appCredentialModel.setId(credentialModel.getId());
			appCredentialModel.setSecretData(credentialModel.getSecretData());
			appCredentialModel.setCredentialData(credentialModel.getCredentialData());
			return appCredentialModel;
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}

	public static AppCredentialModel createAppCredential(String deviceId, String publicKey) {
		AppCredentialModel appCredentialModel = new AppCredentialModel(deviceId, publicKey);
		appCredentialModel.fillCredentialModelFields();
		return appCredentialModel;
	}

	private void fillCredentialModelFields() {
		try {
			setCredentialData(JsonSerialization.writeValueAsString(credentialData));
			setSecretData(JsonSerialization.writeValueAsString(secretData));
			setType(TYPE);
			setCreatedDate(Time.currentTimeMillis());
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}
}
