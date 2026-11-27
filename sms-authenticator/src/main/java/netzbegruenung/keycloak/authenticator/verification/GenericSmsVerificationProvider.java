package netzbegruenung.keycloak.authenticator.verification;

import netzbegruenung.keycloak.authenticator.gateway.SmsServiceFactory;

import org.keycloak.common.util.SecretGenerator;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.theme.Theme;

import java.io.IOException;
import java.util.Map;

/**
 * Generates the code in Keycloak, sends it as message text through the configurable HTTP
 * API, and compares the entered code with the one kept in the authentication session.
 */
public class GenericSmsVerificationProvider implements SmsVerificationProvider {

	static final String NOTE_CODE = "code";
	static final String NOTE_TTL = "ttl";

	@Override
	public void start(SmsVerificationContext context) throws SmsVerificationException {
		Map<String, String> config = context.getConfig();
		int length = Integer.parseInt(config.get("length"));
		int ttl = Integer.parseInt(config.get("ttl"));

		String code = SecretGenerator.getInstance().randomString(length, SecretGenerator.DIGITS);
		AuthenticationSessionModel authSession = context.getAuthenticationSession();
		authSession.setAuthNote(NOTE_CODE, code);
		authSession.setAuthNote(NOTE_TTL, Long.toString(System.currentTimeMillis() + (ttl * 1000L)));

		String smsAuthText;
		try {
			Theme theme = context.getSession().theme().getTheme(Theme.Type.LOGIN);
			smsAuthText = theme.getEnhancedMessages(context.getRealm(), context.getLocale()).getProperty("smsAuthText");
		} catch (IOException e) {
			throw new SmsVerificationException("Failed to load the SMS text from the theme", e);
		}
		String smsText = String.format(smsAuthText, code, Math.floorDiv(ttl, 60));

		SmsServiceFactory.get(config).send(context.getPhoneNumber(), smsText);
	}

	@Override
	public SmsVerificationResult verify(SmsVerificationContext context, String enteredCode) {
		AuthenticationSessionModel authSession = context.getAuthenticationSession();
		String code = authSession.getAuthNote(NOTE_CODE);
		String ttl = authSession.getAuthNote(NOTE_TTL);

		if (code == null || ttl == null) {
			return SmsVerificationResult.ERROR;
		}
		if (!code.equals(enteredCode)) {
			return SmsVerificationResult.INVALID;
		}
		if (Long.parseLong(ttl) < System.currentTimeMillis()) {
			return SmsVerificationResult.EXPIRED;
		}
		return SmsVerificationResult.VALID;
	}
}
