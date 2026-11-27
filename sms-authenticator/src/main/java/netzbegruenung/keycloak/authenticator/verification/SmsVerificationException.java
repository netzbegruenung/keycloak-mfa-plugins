package netzbegruenung.keycloak.authenticator.verification;

public class SmsVerificationException extends Exception {

	public SmsVerificationException(String message) {
		super(message);
	}

	public SmsVerificationException(String message, Throwable cause) {
		super(message, cause);
	}
}
