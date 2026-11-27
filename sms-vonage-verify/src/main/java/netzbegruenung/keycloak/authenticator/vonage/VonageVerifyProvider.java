package netzbegruenung.keycloak.authenticator.vonage;

import netzbegruenung.keycloak.authenticator.gateway.PhoneNumberNormalizer;
import netzbegruenung.keycloak.authenticator.verification.SmsVerificationContext;
import netzbegruenung.keycloak.authenticator.verification.SmsVerificationException;
import netzbegruenung.keycloak.authenticator.verification.SmsVerificationProvider;
import netzbegruenung.keycloak.authenticator.verification.SmsVerificationResult;

import org.jboss.logging.Logger;
import org.keycloak.sessions.AuthenticationSessionModel;

import java.util.Map;
import java.util.regex.Pattern;

/**
 * Lets Vonage Verify generate the code, send it by SMS, and judge the code the user entered.
 * Keycloak never sees the code, it only keeps the id of the verification request.
 */
public class VonageVerifyProvider implements SmsVerificationProvider {

	private static final Logger logger = Logger.getLogger(VonageVerifyProvider.class);

	static final String CONFIG_API_KEY = "vonageVerifyApiKey";
	static final String CONFIG_API_SECRET = "vonageVerifyApiSecret";
	static final String CONFIG_BRAND = "vonageVerifyBrand";
	static final String CONFIG_LOCALE = "vonageVerifyLocale";
	static final String CONFIG_TEMPLATE_ID = "vonageVerifyTemplateId";
	static final String CONFIG_BASE_URL = "vonageVerifyBaseUrl";
	static final String DEFAULT_BASE_URL = "https://api.nexmo.com";

	static final String NOTE_REQUEST_ID = "vonage-verify.request-id";
	static final String NOTE_EXPIRES = "vonage-verify.expires";
	static final String NOTE_PHONE_NUMBER = "vonage-verify.phone-number";

	static final int MIN_CODE_LENGTH = 4;
	static final int MAX_CODE_LENGTH = 10;
	static final int MIN_CHANNEL_TIMEOUT = 15;
	static final int MAX_CHANNEL_TIMEOUT = 900;

	private static final Pattern CODE_PATTERN = Pattern.compile("[A-Za-z0-9]{" + MIN_CODE_LENGTH + "," + MAX_CODE_LENGTH + "}");
	private static final Pattern NON_DIGIT_PATTERN = Pattern.compile("[^0-9]");

	@Override
	public void start(SmsVerificationContext context) throws SmsVerificationException {
		Map<String, String> config = context.getConfig();
		AuthenticationSessionModel authSession = context.getAuthenticationSession();
		String to = toVonageNumber(context.getPhoneNumber(), config.get("countrycode"));

		// Vonage rejects a second verification for a number while one is open. start is
		// called again when the code form is refreshed, the user then keeps using the code
		// of the open request.
		String openRequestId = authSession.getAuthNote(NOTE_REQUEST_ID);
		String expires = authSession.getAuthNote(NOTE_EXPIRES);
		if (openRequestId != null && expires != null
				&& to.equals(authSession.getAuthNote(NOTE_PHONE_NUMBER))
				&& Long.parseLong(expires) > System.currentTimeMillis()) {
			logger.debugf("Vonage Verify request %s is still open, no new code is sent", openRequestId);
			return;
		}
		clearNotes(authSession);

		int codeLength = parseInt(config, "length");
		if (codeLength < MIN_CODE_LENGTH || codeLength > MAX_CODE_LENGTH) {
			throw new SmsVerificationException("Vonage Verify needs a code length between "
				+ MIN_CODE_LENGTH + " and " + MAX_CODE_LENGTH + ", configured is " + codeLength);
		}
		int ttl = parseInt(config, "ttl");
		int channelTimeout = Math.max(MIN_CHANNEL_TIMEOUT, Math.min(MAX_CHANNEL_TIMEOUT, ttl));
		if (channelTimeout != ttl) {
			logger.warnf("Vonage Verify needs a time-to-live between %d and %d seconds, using %d instead of %d",
				MIN_CHANNEL_TIMEOUT, MAX_CHANNEL_TIMEOUT, channelTimeout, ttl);
		}

		String templateId = blankToNull(config.get(CONFIG_TEMPLATE_ID));
		String locale = blankToNull(config.get(CONFIG_LOCALE));
		if (locale == null) {
			locale = VonageLocales.fromLocale(context.getLocale(), templateId != null);
		}

		String requestId = client(config).start(to, required(config, CONFIG_BRAND), codeLength, channelTimeout, locale, templateId);
		authSession.setAuthNote(NOTE_REQUEST_ID, requestId);
		authSession.setAuthNote(NOTE_EXPIRES, Long.toString(System.currentTimeMillis() + (channelTimeout * 1000L)));
		authSession.setAuthNote(NOTE_PHONE_NUMBER, to);
		logger.infof("Started Vonage Verify request %s", requestId);
	}

	@Override
	public SmsVerificationResult verify(SmsVerificationContext context, String enteredCode) {
		AuthenticationSessionModel authSession = context.getAuthenticationSession();
		String requestId = authSession.getAuthNote(NOTE_REQUEST_ID);
		if (requestId == null) {
			return SmsVerificationResult.ERROR;
		}
		// Vonage would reject these as invalid parameters, there is no need to ask
		String code = enteredCode == null ? "" : enteredCode.strip();
		if (!CODE_PATTERN.matcher(code).matches()) {
			return SmsVerificationResult.INVALID;
		}

		SmsVerificationResult result;
		try {
			result = client(context.getConfig()).check(requestId, code);
		} catch (SmsVerificationException e) {
			logger.error("Failed to check the code with Vonage Verify", e);
			return SmsVerificationResult.ERROR;
		}
		if (result == SmsVerificationResult.VALID || result == SmsVerificationResult.EXPIRED) {
			// the request is finished, the next start has to send a new code
			clearNotes(authSession);
		}
		return result;
	}

	/** Vonage wants the E.164 format without the leading + or 00. */
	static String toVonageNumber(String phoneNumber, String defaultCountryCode) throws SmsVerificationException {
		String normalized = PhoneNumberNormalizer.toE164(phoneNumber, defaultCountryCode);
		if (normalized == null) {
			throw new SmsVerificationException("No phone number to send the code to");
		}
		normalized = normalized.strip();
		if (normalized.startsWith("00")) {
			normalized = normalized.substring(2);
		}
		String digits = NON_DIGIT_PATTERN.matcher(normalized).replaceAll("");
		if (digits.isEmpty()) {
			throw new SmsVerificationException("No phone number to send the code to");
		}
		return digits;
	}

	private static VonageVerifyClient client(Map<String, String> config) throws SmsVerificationException {
		String baseUrl = blankToNull(config.get(CONFIG_BASE_URL));
		return new VonageVerifyClient(
			baseUrl == null ? DEFAULT_BASE_URL : baseUrl,
			required(config, CONFIG_API_KEY),
			required(config, CONFIG_API_SECRET));
	}

	private static void clearNotes(AuthenticationSessionModel authSession) {
		authSession.removeAuthNote(NOTE_REQUEST_ID);
		authSession.removeAuthNote(NOTE_EXPIRES);
		authSession.removeAuthNote(NOTE_PHONE_NUMBER);
	}

	private static String required(Map<String, String> config, String name) throws SmsVerificationException {
		String value = blankToNull(config.get(name));
		if (value == null) {
			throw new SmsVerificationException("Vonage Verify is not configured, " + name + " is missing");
		}
		return value;
	}

	private static int parseInt(Map<String, String> config, String name) throws SmsVerificationException {
		try {
			return Integer.parseInt(config.get(name).strip());
		} catch (RuntimeException e) {
			throw new SmsVerificationException("The setting " + name + " is not a number: " + config.get(name));
		}
	}

	private static String blankToNull(String value) {
		return value == null || value.isBlank() ? null : value.strip();
	}
}
