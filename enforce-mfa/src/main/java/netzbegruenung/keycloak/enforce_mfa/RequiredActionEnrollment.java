package netzbegruenung.keycloak.enforce_mfa;

import org.keycloak.authentication.requiredactions.WebAuthnPasswordlessRegisterFactory;
import org.keycloak.authentication.requiredactions.WebAuthnRegisterFactory;
import org.keycloak.credential.OTPCredentialProviderFactory;
import org.keycloak.credential.WebAuthnCredentialProviderFactory;
import org.keycloak.credential.WebAuthnPasswordlessCredentialProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

import java.util.Map;

/**
 * Determines whether a required action's enrollment can be considered satisfied (credential present).
 */
public final class RequiredActionEnrollment {

	private static final Map<String, String> CREDENTIAL_TYPE_BY_REQUIRED_ACTION_ID = Map.of(
		UserModel.RequiredAction.CONFIGURE_TOTP.name(), OTPCredentialProviderFactory.PROVIDER_ID,
		WebAuthnRegisterFactory.PROVIDER_ID, WebAuthnCredentialProviderFactory.PROVIDER_ID,
		WebAuthnPasswordlessRegisterFactory.PROVIDER_ID, WebAuthnPasswordlessCredentialProviderFactory.PROVIDER_ID,
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
