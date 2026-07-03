package netzbegruenung.keycloak.enforce_mfa;

import org.keycloak.authentication.requiredactions.WebAuthnPasswordlessRegisterFactory;
import org.keycloak.authentication.requiredactions.WebAuthnRegisterFactory;
import org.keycloak.models.Constants;
import org.keycloak.models.UserModel;
import org.keycloak.models.credential.OTPCredentialModel;
import org.keycloak.models.credential.WebAuthnCredentialModel;

import java.util.List;
import java.util.Map;

/**
 * Shared config keys, admin multiselect option lists, and parsing of multivalued authenticator config (Keycloak delimiter).
 */
public final class EnforceMfaShared {

	private EnforceMfaShared() {
	}

	/** {@link ConditionalEnforceMfaAuthenticator} config: multiselect required actions shown on the screen. */
	public static final String CONFIG_OFFERED = "offeredRequiredActions";
	/** Same key as {@link EnforceMfaAuthenticator#CONFIG_OPTIONAL_NAME}. */
	public static final String CONFIG_OPTIONAL_NAME = "mfaSetupOptional";

	/** Stored credential type ids for {@link MfaCredentialConditionFactory} admin UI (not credential provider SPI ids). */
	public static final List<String> CREDENTIAL_TYPE_OPTIONS = List.of(
		OTPCredentialModel.TYPE, // "otp"
		WebAuthnCredentialModel.TYPE_TWOFACTOR, // "webauthn"
		WebAuthnCredentialModel.TYPE_PASSWORDLESS, // "webauthn-passwordless"
		"email-authenticator", /* from mesutpiskin/keycloak-2fa-email-authenticator */
		"mobile-number" /* from netzbegruenung/keycloak-mfa-plugins/sms-authenticator */
	);

	/** Required action ids for {@link ConditionalEnforceMfaAuthenticatorFactory} admin UI. */
	public static final List<String> REQUIRED_ACTION_OPTIONS = List.of(
		UserModel.RequiredAction.CONFIGURE_TOTP.name(),
		WebAuthnRegisterFactory.PROVIDER_ID,
		WebAuthnPasswordlessRegisterFactory.PROVIDER_ID,
		"email-authenticator-setup", /* from mesutpiskin/keycloak-2fa-email-authenticator */
		"mobile_number_config" /* from netzbegruenung/keycloak-mfa-plugins/sms-authenticator */
	);

	/**
	 * Lit une entrée de config authenticator telle que stockée par l’admin (valeurs jointes avec
	 * {@link Constants#CFG_DELIMITER}).
	 */
	public static List<String> splitMultivalued(Map<String, String> cfg, String key) {
		if (cfg == null) {
			return List.of();
		}
		String v = cfg.get(key);
		if (v == null || v.isBlank()) {
			return List.of();
		}
		return Constants.CFG_DELIMITER_PATTERN.splitAsStream(v)
			.map(String::trim)
			.filter(s -> !s.isEmpty())
			.toList();
	}
}
