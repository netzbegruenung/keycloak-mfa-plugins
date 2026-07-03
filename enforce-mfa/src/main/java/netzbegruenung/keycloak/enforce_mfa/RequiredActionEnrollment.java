package netzbegruenung.keycloak.enforce_mfa;

import org.keycloak.authentication.requiredactions.WebAuthnPasswordlessRegisterFactory;
import org.keycloak.authentication.requiredactions.WebAuthnRegisterFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.credential.OTPCredentialModel;
import org.keycloak.models.credential.WebAuthnCredentialModel;

import java.util.Map;

/**
 * Determines whether a required action's enrollment can be considered satisfied (credential present).
 */
public final class RequiredActionEnrollment {

	private static final Map<String, String> CREDENTIAL_TYPE_BY_REQUIRED_ACTION_ID = Map.of(
		UserModel.RequiredAction.CONFIGURE_TOTP.name(), OTPCredentialModel.TYPE,
		WebAuthnRegisterFactory.PROVIDER_ID, WebAuthnCredentialModel.TYPE_TWOFACTOR,
		WebAuthnPasswordlessRegisterFactory.PROVIDER_ID, WebAuthnCredentialModel.TYPE_PASSWORDLESS,
		"email-authenticator-setup", "email-authenticator", /* from mesutpiskin/keycloak-2fa-email-authenticator */
		"mobile_number_config", "mobile-number", /* from netzbegruenung/keycloak-mfa-plugins/sms-authenticator */
		"phone_validation_config", "mobile-number" /* from netzbegruenung/keycloak-mfa-plugins/sms-authenticator */
	);

	private RequiredActionEnrollment() {
	}

	public static boolean isSatisfied(KeycloakSession session, RealmModel realm, UserModel user, String requiredActionProviderId) {
		String cred = CREDENTIAL_TYPE_BY_REQUIRED_ACTION_ID.get(requiredActionProviderId);
		if (cred != null) {
			return user.credentialManager().isConfiguredFor(cred);
		}
		return user.getRequiredActionsStream().noneMatch(requiredActionProviderId::equals);
	}
}
