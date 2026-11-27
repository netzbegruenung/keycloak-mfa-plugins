package netzbegruenung.keycloak.authenticator.verification;

import org.keycloak.provider.Provider;

/**
 * Sends a one time code to a phone number and judges the code the user entered.
 *
 * Implementations decide who generates the code. The default provider generates it in
 * Keycloak and sends it as message text. A provider for a verification service lets the
 * service generate the code, and asks the service whether the entered code is correct.
 *
 * Any state needed between {@link #start} and {@link #verify} (the code, a request id) is
 * kept by the provider in the authentication session, see
 * {@link SmsVerificationContext#getAuthenticationSession()}.
 */
public interface SmsVerificationProvider extends Provider {

	/**
	 * Send a code to the phone number in the context.
	 *
	 * This is called every time the code form is about to be shown, which includes a page
	 * refresh. A provider that must not start a second verification while one is open has
	 * to detect that from its own state in the authentication session.
	 *
	 * @throws SmsVerificationException if the code could not be sent
	 */
	void start(SmsVerificationContext context) throws SmsVerificationException;

	/**
	 * Judge the code the user entered.
	 *
	 * @param enteredCode the submitted code, may be null
	 */
	SmsVerificationResult verify(SmsVerificationContext context, String enteredCode);

	@Override
	default void close() {
	}
}
