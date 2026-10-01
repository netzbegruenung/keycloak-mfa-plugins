/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @author Niko Köbler, https://www.n-k.de, @dasniko
 * @author Netzbegruenung e.V.
 * @author verdigado eG
 */

package netzbegruenung.keycloak.authenticator;

import netzbegruenung.keycloak.authenticator.credentials.SmsAuthCredentialModel;
import netzbegruenung.keycloak.authenticator.gateway.SmsServiceFactory;

import org.jboss.logging.Logger;
import org.keycloak.authentication.CredentialRegistrator;
import org.keycloak.authentication.RequiredActionContext;
import org.keycloak.authentication.RequiredActionProvider;
import org.keycloak.common.util.SecretGenerator;
import org.keycloak.common.util.Time;
import org.keycloak.credential.CredentialProvider;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserCredentialModel;
import org.keycloak.models.UserModel;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.theme.Theme;

import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Properties;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;


public class PhoneValidationRequiredAction implements RequiredActionProvider, CredentialRegistrator {
	private static final Logger logger = Logger.getLogger(PhoneValidationRequiredAction.class);
	public static final String PROVIDER_ID = "phone_validation_config";

	/**
	 * Epoch seconds ({@link Time#currentTimeSeconds()}) of the last SMS send. Written both as a user attribute
	 * (so the debounce holds across browsers, tabs and incognito sessions — it is per account, not per
	 * auth session) and as an auth session note under the same key, so a fast follow-up request in the
	 * same flow still sees a timestamp without waiting on a user storage round-trip.
	 */
	public static final String LAST_OTP_SENT = "sms_last_otp_sent_epoch";
	/** Sends completed so far, for the exponential backoff tier. User attribute; survives sessions. */
	public static final String OTP_SEND_COUNT = "sms_otp_send_count";
	/** Form parameter naming the resend submit button in login-sms.ftl. */
	public static final String RESEND_PARAM = "resend";

	/**
	 * Baseline seconds between the 1st and 2nd SMS. Also the value pre-filled into the sms-2fa config
	 * field, so the admin console and this fallback cannot drift apart.
	 */
	public static final long DEFAULT_DEBOUNCE_SECONDS = 30;
	/**
	 * Upper bound (seconds) on the grown debounce gap, used when neither the sms-2fa config field nor
	 * {@link #ENV_DEBOUNCE_MAX_CAP_SECONDS} supplies one. Also the value pre-filled into that config
	 * field. Six hours: the doubling stops growing there, so a determined abuser is held to a handful of
	 * SMS per day while a genuinely stuck user still gets a retry window within the same day.
	 */
	public static final long FALLBACK_DEBOUNCE_MAX_CAP_SECONDS = 6L * 60L * 60L;
	/**
	 * Keycloak process environment variable: upper bound (seconds) for the resend debounce when the
	 * sms-2fa execution leaves {@code smsResendDebounceMaxCapSeconds} empty. Positive integer; unset or
	 * invalid falls back to {@link #FALLBACK_DEBOUNCE_MAX_CAP_SECONDS}.
	 */
	public static final String ENV_DEBOUNCE_MAX_CAP_SECONDS = "KC_SMS_PHONE_VALIDATION_RESEND_DEBOUNCE_MAX_CAP_SECONDS";
	private static final long DEFAULT_DEBOUNCE_MAX_CAP_SECONDS = resolveMaxCapFromEnvironment();


	private static long resolveMaxCapFromEnvironment() {
		String raw = System.getenv(ENV_DEBOUNCE_MAX_CAP_SECONDS);
		long resolved = parsePositiveLong(raw, FALLBACK_DEBOUNCE_MAX_CAP_SECONDS,
			() -> logger.warnf("Invalid or non-positive %s=%s, using fallback %d seconds",
				ENV_DEBOUNCE_MAX_CAP_SECONDS, raw, FALLBACK_DEBOUNCE_MAX_CAP_SECONDS));
		logger.infof("PhoneValidationRequiredAction init: debounce max cap = %d seconds (%s=%s)",
			resolved, ENV_DEBOUNCE_MAX_CAP_SECONDS, raw == null || raw.isBlank() ? "<unset>" : raw);
		return resolved;
	}

	@Override
	public void evaluateTriggers(RequiredActionContext context) {
	}

	@Override
	public void requiredActionChallenge(RequiredActionContext context) {
		context.getAuthenticationSession().addRequiredAction(PhoneNumberRequiredAction.PROVIDER_ID);
		try {
			UserModel user = context.getUser();
			RealmModel realm = context.getRealm();

			AuthenticationSessionModel authSession = context.getAuthenticationSession();
			// TODO: get the alias from somewhere else or move config into realm or application scope
			AuthenticatorConfigModel config = context.getRealm().getAuthenticatorConfigByAlias("sms-2fa");

			String mobileNumber = authSession.getAuthNote("mobile_number");
			logger.infof("Validating phone number: %s of user: %s", mobileNumber, user.getUsername());

			long baselineSeconds = resolveBaselineDebounceSeconds(config);
			long maxCapSeconds = resolveDebounceMaxCapSeconds(config);
			// Exponential debounce between sends, enforced per account (see LAST_OTP_SENT).
			if (canSendOtp(user, authSession, baselineSeconds, maxCapSeconds)) {
				sendSmsAndCreateForm(context, authSession, config, mobileNumber);
				logger.info("Initial SMS OTP sent for user " + user.getUsername());
			} else {
				// If debouncing prevents sending, show form with a message indicating remaining
				// time
				long secondsRemaining = getSecondsRemaining(user, authSession, baselineSeconds, maxCapSeconds);
				Locale locale = context.getSession().getContext().resolveLocale(user);
				Properties messages = context.getSession().theme().getTheme(Theme.Type.LOGIN)
					.getEnhancedMessages(realm, locale);
				Response challenge = context.form()
						.setAttribute("realm", realm)
						.setError("smsDebounceMessage", formatWaitHumanReadable(secondsRemaining, messages))
						.createForm(SmsAuthenticator.TPL_CODE);
				context.challenge(challenge);
				logger.infof("SMS resend rejected for user %s (%d seconds remaining)", user.getUsername(),
						secondsRemaining);
			}
		} catch (Exception e) {
			logger.error(e.getMessage(), e);
			context.failure();
		}
	}

	/**
	 * @param baselineSeconds initial gap after the 1st SMS; each further send doubles the required wait,
	 *        capped at {@code maxCapSeconds}. A baseline of 0 disables debouncing entirely.
	 */
	private boolean canSendOtp(UserModel user, AuthenticationSessionModel authSession, long baselineSeconds,
			long maxCapSeconds) {
		long lastTime = readLastOtpSentEpoch(user, authSession);
		if (lastTime <= 0) {
			return true;
		}
		long requiredGap = requiredSecondsBetweenSends(completedSendCount(user, lastTime), baselineSeconds,
			maxCapSeconds);
		return requiredGap <= 0 || Time.currentTimeSeconds() - lastTime >= requiredGap;
	}

	private long getSecondsRemaining(UserModel user, AuthenticationSessionModel authSession, long baselineSeconds,
			long maxCapSeconds) {
		long lastTime = readLastOtpSentEpoch(user, authSession);
		if (lastTime <= 0) {
			return 0;
		}
		long requiredGap = requiredSecondsBetweenSends(completedSendCount(user, lastTime), baselineSeconds,
			maxCapSeconds);
		return Math.max(0, requiredGap - (Time.currentTimeSeconds() - lastTime));
	}

	/**
	 * After {@code completedSends} SMS sends, seconds required before the next send (0 = no wait).
	 * Gaps follow {@code baseline * 2^(completedSends - 1)}, capped at {@code maxCapSeconds}.
	 */
	static long requiredSecondsBetweenSends(int completedSends, long baselineSeconds, long maxCapSeconds) {
		long baseline = Math.max(0, baselineSeconds);
		if (completedSends <= 0 || baseline == 0) {
			return 0;
		}
		long cap = Math.max(1, maxCapSeconds);
		long gap = baseline;
		// Guard keeps gap below cap before each doubling, so this cannot overflow.
		for (int i = 1; i < completedSends && gap < cap; i++) {
			gap <<= 1;
		}
		return Math.min(gap, cap);
	}

	/**
	 * Sends already completed, for tiering. With no send timestamp stored, a stray counter is ignored;
	 * with a timestamp but no counter, assume one send.
	 */
	private static int completedSendCount(UserModel user, long lastOtpSentEpoch) {
		if (lastOtpSentEpoch <= 0) {
			return 0;
		}
		long stored = parsePositiveLong(user.getFirstAttribute(OTP_SEND_COUNT), 0,
			() -> logger.warnf("Invalid user attribute %s, treating send count as 0", OTP_SEND_COUNT));
		return stored > 0 ? (int) Math.min(stored, Integer.MAX_VALUE) : 1;
	}

	/**
	 * Latest SMS-send epoch: max of the user attribute (persisted, cross-session) and the auth session
	 * note (in-memory for this flow), so neither a new browser session nor a not-yet-visible user write
	 * can produce a free send.
	 */
	private long readLastOtpSentEpoch(UserModel user, AuthenticationSessionModel authSession) {
		long fromUser = parsePositiveLong(user.getFirstAttribute(LAST_OTP_SENT), 0,
			() -> logger.warnf("Invalid user attribute %s, ignoring debounce timestamp", LAST_OTP_SENT));
		long fromSession = authSession == null ? 0
			: parsePositiveLong(authSession.getAuthNote(LAST_OTP_SENT), 0, () -> {
			});
		return Math.max(fromUser, fromSession);
	}

	private static long parsePositiveLong(String raw, long fallback, Runnable onInvalid) {
		if (raw == null || raw.isBlank()) {
			return fallback;
		}
		try {
			long value = Long.parseLong(raw.trim());
			if (value > 0) {
				return value;
			}
		} catch (NumberFormatException ignored) {
			// fall through to onInvalid
		}
		onInvalid.run();
		return fallback;
	}

	private long resolveBaselineDebounceSeconds(AuthenticatorConfigModel config) {
		if (config == null || config.getConfig() == null) {
			return DEFAULT_DEBOUNCE_SECONDS;
		}
		String raw = config.getConfig().get(SmsAuthenticatorFactory.SMS_RESEND_DEBOUNCE_SECONDS);
		if (raw == null || raw.isBlank()) {
			return DEFAULT_DEBOUNCE_SECONDS;
		}
		try {
			long seconds = Long.parseLong(raw.trim());
			// 0 is meaningful here: it disables debouncing.
			return seconds >= 0 ? seconds : DEFAULT_DEBOUNCE_SECONDS;
		} catch (NumberFormatException e) {
			logger.warnf("Invalid %s in sms-2fa config, using default %d",
				SmsAuthenticatorFactory.SMS_RESEND_DEBOUNCE_SECONDS, DEFAULT_DEBOUNCE_SECONDS);
			return DEFAULT_DEBOUNCE_SECONDS;
		}
	}

	private long resolveDebounceMaxCapSeconds(AuthenticatorConfigModel config) {
		if (config == null || config.getConfig() == null) {
			return DEFAULT_DEBOUNCE_MAX_CAP_SECONDS;
		}
		return parsePositiveLong(config.getConfig().get(SmsAuthenticatorFactory.SMS_RESEND_DEBOUNCE_MAX_CAP_SECONDS),
			DEFAULT_DEBOUNCE_MAX_CAP_SECONDS,
			() -> logger.warnf("Invalid %s in sms-2fa config, using default %d",
				SmsAuthenticatorFactory.SMS_RESEND_DEBOUNCE_MAX_CAP_SECONDS, DEFAULT_DEBOUNCE_MAX_CAP_SECONDS));
	}

	/**
	 * Human-readable wait text for the login theme. Under one hour: minutes and/or seconds. At one hour
	 * or more: hours and minutes only, with any sub-minute remainder rounded up, so the message is never
	 * shorter than the actual wait.
	 */
	static String formatWaitHumanReadable(long totalSeconds, Properties messages) {
		if (totalSeconds <= 0) {
			return msg(messages, "smsDebounceWaitMoment", "a moment");
		}
		long hours = totalSeconds / 3600L;
		long remainder = totalSeconds % 3600L;
		List<String> parts = new ArrayList<>(2);

		if (hours > 0) {
			long minutes = remainder == 0 ? 0 : (remainder + 59L) / 60L;
			if (minutes >= 60L) {
				hours++;
				minutes = 0;
			}
			parts.add(plural(messages, hours, "smsDebounce1Hour", "1 hour", "smsDebounceNHours", "{0} hours"));
			if (minutes > 0) {
				parts.add(plural(messages, minutes, "smsDebounce1Minute", "1 minute", "smsDebounceNMinutes",
					"{0} minutes"));
			}
		} else {
			long minutes = remainder / 60L;
			long seconds = remainder % 60L;
			if (minutes > 0) {
				parts.add(plural(messages, minutes, "smsDebounce1Minute", "1 minute", "smsDebounceNMinutes",
					"{0} minutes"));
			}
			if (seconds > 0) {
				parts.add(plural(messages, seconds, "smsDebounce1Second", "1 second", "smsDebounceNSeconds",
					"{0} seconds"));
			}
		}

		if (parts.isEmpty()) {
			return msg(messages, "smsDebounceWaitMoment", "a moment");
		}
		if (parts.size() == 1) {
			return parts.get(0);
		}
		return msg(messages, "smsDebounceJoin2", "{0} {1}", parts.get(0), parts.get(1));
	}

	private static String plural(Properties messages, long value, String oneKey, String oneDefault, String manyKey,
			String manyDefault) {
		return value == 1L
			? msg(messages, oneKey, oneDefault)
			: msg(messages, manyKey, manyDefault, value);
	}

	private static String msg(Properties messages, String key, String defaultPattern, Object... args) {
		String pattern = messages == null ? null : messages.getProperty(key);
		if (pattern == null || pattern.isBlank()) {
			pattern = defaultPattern;
		}
		return args.length == 0 ? pattern : MessageFormat.format(pattern, args);
	}


	private void sendSmsAndCreateForm(RequiredActionContext context, AuthenticationSessionModel authSession,
			AuthenticatorConfigModel config, String mobileNumber) throws Exception {
		int length = Integer.parseInt(config.getConfig().get("length"));
		int ttl = Integer.parseInt(config.getConfig().get("ttl"));

		String code = SecretGenerator.getInstance().randomString(length, SecretGenerator.DIGITS);
		authSession.setAuthNote("code", code);
		authSession.setAuthNote("ttl", Long.toString(System.currentTimeMillis() + (ttl * 1000L)));

		Theme theme = context.getSession().theme().getTheme(Theme.Type.LOGIN);
		Locale locale = context.getSession().getContext().resolveLocale(context.getUser());
		String smsAuthText = theme.getEnhancedMessages(context.getRealm(), locale).getProperty("smsAuthText");
		String smsText = String.format(smsAuthText, code, Math.floorDiv(ttl, 60));

		SmsServiceFactory.get(config.getConfig()).send(mobileNumber, smsText);
		// Only after the gateway accepted it: a failed send must not burn the user's debounce window.
		recordOtpSent(context.getUser(), authSession);

		context.getUser().removeRequiredAction(PhoneValidationRequiredAction.PROVIDER_ID);

		Response challenge = context.form()
				.setAttribute("realm", context.getRealm())
				.createForm(SmsAuthenticator.TPL_CODE);
		context.challenge(challenge);
	}

	private void recordOtpSent(UserModel user, AuthenticationSessionModel authSession) {
		String sentEpoch = String.valueOf(Time.currentTimeSeconds());
		// Session note first, so the next request in this flow debounces without waiting on user storage.
		authSession.setAuthNote(LAST_OTP_SENT, sentEpoch);
		user.setSingleAttribute(LAST_OTP_SENT, sentEpoch);
		// ponytail: read-modify-write on a user attribute, so two truly simultaneous sends can both
		// read the same count and under-count by one. The timestamp above still gates them. Move the
		// counter to a stored credential (or a DB-side increment) if exact tiering ever matters.
		long previous = parsePositiveLong(user.getFirstAttribute(OTP_SEND_COUNT), 0, () -> {
		});
		user.setSingleAttribute(OTP_SEND_COUNT, String.valueOf(previous + 1));
	}

	@Override
	public void processAction(RequiredActionContext context) {
		MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
		if (formData.containsKey(RESEND_PARAM)) {
			// The required-action endpoint routes on the session code, not the HTTP method, so any request
			// carrying it lands here — a resend has to re-enter the challenge explicitly. That re-applies
			// the debounce before sending, so this is not a way around it.
			logger.debugf("SMS resend requested by user %s", context.getUser().getUsername());
			requiredActionChallenge(context);
			return;
		}
		String enteredCode = formData.getFirst("code");

		AuthenticationSessionModel authSession = context.getAuthenticationSession();
		String mobileNumber = authSession.getAuthNote("mobile_number");
		String code = authSession.getAuthNote("code");
		String ttl = authSession.getAuthNote("ttl");

		if (code == null || ttl == null || enteredCode == null) {
			logger.warn("Phone number is not set");
			handleInvalidSmsCode(context);
			return;
		}

		boolean isValid = enteredCode.equals(code);
		if (isValid && Long.parseLong(ttl) > System.currentTimeMillis()) {
			// valid
			SmsAuthCredentialProvider smnp = (SmsAuthCredentialProvider) context.getSession().getProvider(CredentialProvider.class, "mobile-number");
			if (!smnp.isConfiguredFor(context.getRealm(), context.getUser(), SmsAuthCredentialModel.TYPE)) {
				smnp.createCredential(context.getRealm(), context.getUser(), SmsAuthCredentialModel.createSmsAuthenticator(mobileNumber));
			} else {
				smnp.updateCredential(
					context.getRealm(),
					context.getUser(),
					new UserCredentialModel("random_id", "mobile-number", mobileNumber)
				);
			}
			context.getAuthenticationSession().removeRequiredAction(PhoneNumberRequiredAction.PROVIDER_ID);
			handlePhoneToAttribute(context, mobileNumber);
			clearDebounceState(context.getUser(), authSession);
			context.success();
		} else {
			// invalid or expired
			handleInvalidSmsCode(context);
		}
	}

	/** The number is proven at this point, so a later legitimate change starts from the base gap again. */
	private void clearDebounceState(UserModel user, AuthenticationSessionModel authSession) {
		authSession.removeAuthNote(LAST_OTP_SENT);
		user.removeAttribute(LAST_OTP_SENT);
		user.removeAttribute(OTP_SEND_COUNT);
	}

	private void handlePhoneToAttribute(RequiredActionContext context, String mobileNumber) {
		AuthenticatorConfigModel config = context.getRealm().getAuthenticatorConfigByAlias("sms-2fa");
		if (config == null) {
			logger.warn("No config alias sms-2fa found, skip phone number to attribute check");
		} else {
			if (Boolean.parseBoolean(config.getConfig().get("storeInAttribute"))) {
				context.getUser().setSingleAttribute("mobile_number", mobileNumber);
			}
		}
	}

	private void handleInvalidSmsCode(RequiredActionContext context) {
		Response challenge = context
			.form()
			.setAttribute("realm", context.getRealm())
			.setError("smsAuthCodeInvalid")
			.createForm(SmsAuthenticator.TPL_CODE);
		context.challenge(challenge);
	}

	@Override
	public void close() {
	}

	@Override
	public String getCredentialType(KeycloakSession keycloakSession, AuthenticationSessionModel authenticationSessionModel) {
		return SmsAuthCredentialModel.TYPE;
	}
}
