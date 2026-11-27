package netzbegruenung.keycloak.authenticator.verification;

public enum SmsVerificationResult {
	/** The entered code is correct. */
	VALID,
	/** The entered code is wrong, the user may try again. */
	INVALID,
	/** The code can no longer be used, a new one has to be sent. */
	EXPIRED,
	/** The code could not be judged, e.g. no code was sent or the service is not reachable. */
	ERROR
}
