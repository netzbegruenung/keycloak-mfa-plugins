package netzbegruenung.keycloak.app.credentials;

import org.junit.jupiter.api.Test;
import org.keycloak.credential.CredentialModel;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

/**
 * createFromCredentialModel is what AppCredentialProvider#getCredentialFromModel delegates to,
 * which the Account Console calls per credential to build its display representation - this
 * exercises that display fallback directly, without needing a full Keycloak/browser integration
 * test.
 */
class AppCredentialModelTest {

	@Test
	void reconstructedModelDefaultsLabelToDeviceOsForDisplay() throws Exception {
		AppCredentialModel deviceModel = AppCredentialModel.createAppCredential(
			"public-key", "device-1", "android", "RSA", "SHA256withRSA", "push-id");

		// Simulates what's actually persisted: userLabel stays null unless a user renames it via
		// the Account Console's own rename feature - createAppCredential never sets one.
		CredentialModel stored = new CredentialModel();
		stored.setId("credential-1");
		stored.setType(AppCredentialModel.TYPE);
		stored.setCredentialData(deviceModel.getCredentialData());
		stored.setCreatedDate(deviceModel.getCreatedDate());
		assertNull(stored.getUserLabel());

		AppCredentialModel reconstructed = AppCredentialModel.createFromCredentialModel(stored);

		assertEquals("android", reconstructed.getUserLabel());
	}

	@Test
	void reconstructedModelPrefersDeviceOsEvenOverAStoredCustomLabel() throws Exception {
		AppCredentialModel deviceModel = AppCredentialModel.createAppCredential(
			"public-key", "device-1", "android", "RSA", "SHA256withRSA", "push-id");

		CredentialModel stored = new CredentialModel();
		stored.setId("credential-1");
		stored.setType(AppCredentialModel.TYPE);
		stored.setCredentialData(deviceModel.getCredentialData());
		stored.setCreatedDate(deviceModel.getCreatedDate());
		stored.setUserLabel("My Phone");

		AppCredentialModel reconstructed = AppCredentialModel.createFromCredentialModel(stored);

		assertEquals("android", reconstructed.getUserLabel());
	}
}
