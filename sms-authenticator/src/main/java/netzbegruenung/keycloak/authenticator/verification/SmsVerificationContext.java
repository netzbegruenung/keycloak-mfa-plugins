package netzbegruenung.keycloak.authenticator.verification;

import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.sessions.AuthenticationSessionModel;

import java.util.Locale;
import java.util.Map;

/**
 * What a {@link SmsVerificationProvider} gets to work with for one verification.
 */
public class SmsVerificationContext {

	private final KeycloakSession session;
	private final RealmModel realm;
	private final UserModel user;
	private final AuthenticationSessionModel authenticationSession;
	private final Map<String, String> config;
	private final String phoneNumber;

	public SmsVerificationContext(KeycloakSession session, RealmModel realm, UserModel user,
			AuthenticationSessionModel authenticationSession, Map<String, String> config, String phoneNumber) {
		this.session = session;
		this.realm = realm;
		this.user = user;
		this.authenticationSession = authenticationSession;
		this.config = config;
		this.phoneNumber = phoneNumber;
	}

	public KeycloakSession getSession() {
		return session;
	}

	public RealmModel getRealm() {
		return realm;
	}

	public UserModel getUser() {
		return user;
	}

	/** Where a provider keeps its state between start and verify, as auth notes. */
	public AuthenticationSessionModel getAuthenticationSession() {
		return authenticationSession;
	}

	/** The config of the SMS authenticator execution, including the provider's own properties. */
	public Map<String, String> getConfig() {
		return config;
	}

	/** The phone number as stored for the user. It is not normalized. */
	public String getPhoneNumber() {
		return phoneNumber;
	}

	public Locale getLocale() {
		return session.getContext().resolveLocale(user);
	}
}
