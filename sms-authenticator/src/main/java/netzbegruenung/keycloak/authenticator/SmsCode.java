package netzbegruenung.keycloak.authenticator;

import org.jboss.logging.Logger;
import org.keycloak.common.util.SecretGenerator;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.SingleUseObjectProvider;
import org.keycloak.models.UserModel;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HashMap;
import java.util.Map;

/**
 * Issues and verifies the SMS one-time code and rate-limits sends and guesses.
 * <p>
 * All state is kept per user in Keycloak's {@link SingleUseObjectProvider} (cluster-wide,
 * self-expiring), not in the auth session, so it holds across login restarts, browser
 * tabs and nodes:
 * <ul>
 * <li>{@code code.<userId>}: the code, its expiry, the number it went to and the wrong
 * guesses so far. Re-running a challenge re-sends this code instead of replacing it: SMS
 * delivery is neither ordered nor reliable, so the user must be able to use whichever
 * message arrives. The expiry is never extended; with less than
 * {@link #MIN_REMAINING_SECONDS} left a fresh code is issued. After {@link #MAX_ATTEMPTS}
 * wrong guesses the code is discarded.</li>
 * <li>{@code cooldown.<userId>}: set atomically ({@code putIfAbsent}) on every send for
 * {@code resendCooldown} seconds; a request that finds it sends nothing and does not
 * count. This also serialises parallel requests.</li>
 * <li>{@code sends.<userId>}: sends within the current {@code ttl} window. More than
 * {@code resendLimit + 1} of them block code requests for {@code resendBlockDuration}
 * seconds ({@code resend-block.<userId>}). A code already delivered stays valid until its
 * expiry.</li>
 * <li>{@code verify.<userId>}: one verification per second, atomically, so parallel
 * guessing cannot outrun the attempt counter.</li>
 * </ul>
 * A successful verification clears the code, the send counter and the cooldown.
 */
final class SmsCode {

	private static final Logger logger = Logger.getLogger(SmsCode.class);

	static final String RESEND_LIMIT_CONFIG = "resendLimit";
	static final String RESEND_BLOCK_DURATION_CONFIG = "resendBlockDuration";
	static final String RESEND_COOLDOWN_CONFIG = "resendCooldown";
	static final String DEFAULT_LENGTH = "6";
	static final String DEFAULT_TTL = "300";
	static final String DEFAULT_RESEND_LIMIT = "4";
	static final String DEFAULT_RESEND_BLOCK_DURATION = "900";
	static final String DEFAULT_RESEND_COOLDOWN = "60";
	/** Below this remaining lifetime a re-send issues a fresh code rather than a nearly expired one. */
	static final int MIN_REMAINING_SECONDS = 60;
	/** Wrong guesses after which the code is discarded and a new one has to be requested. */
	static final int MAX_ATTEMPTS = 5;
	/** Minimum seconds between two verifications of one user's code. */
	private static final int VERIFY_INTERVAL_SECONDS = 1;
	/** Keeps an expired code entry around so the user is told "expired" rather than sent a new code. */
	private static final int EXPIRED_GRACE_SECONDS = 60;

	private static final String KEY_PREFIX = "sms-authenticator.";
	private static final String CODE_KEY = KEY_PREFIX + "code.";
	private static final String SENDS_KEY = KEY_PREFIX + "sends.";
	private static final String COOLDOWN_KEY = KEY_PREFIX + "cooldown.";
	private static final String BLOCK_KEY = KEY_PREFIX + "resend-block.";
	private static final String VERIFY_KEY = KEY_PREFIX + "verify.";

	private static final String CODE = "code";
	private static final String EXPIRES_AT = "expiresAt";
	private static final String RECIPIENT = "recipient";
	private static final String ATTEMPTS = "attempts";
	private static final String COUNT = "count";
	private static final String WINDOW_START = "windowStart";
	private static final String SENT_AT = "sentAt";
	private static final String BLOCKED_UNTIL = "blockedUntil";

	/**
	 * Outcome of {@link #issue}: a code to send, or nothing because the user is blocked or
	 * still inside the cooldown. {@code resent} is true when the user already had a code,
	 * i.e. this send was requested again and deserves feedback on the page.
	 * {@code nextSendAtMillis} is when the page may offer a re-send again; {@code resendsLeft}
	 * how many more sends the current window allows before the block.
	 */
	record Outcome(String code, long expiresAtMillis, long blockedUntilMillis, long nextSendAtMillis, boolean resent,
				   int resendsLeft) {

		static Outcome issued(String code, long expiresAtMillis, long nextSendAtMillis, boolean resent, int resendsLeft) {
			return new Outcome(code, expiresAtMillis, 0L, nextSendAtMillis, resent, resendsLeft);
		}

		static Outcome blocked(long blockedUntilMillis) {
			return new Outcome(null, 0L, blockedUntilMillis, blockedUntilMillis, false, 0);
		}

		static Outcome coolingDown(long nextSendAtMillis) {
			return new Outcome(null, 0L, 0L, nextSendAtMillis, false, 0);
		}

		boolean blocked() {
			return blockedUntilMillis > 0L;
		}

		boolean coolingDown() {
			return code == null && !blocked();
		}

		/** Seconds (at least 1 while positive) until a re-send is offered again; 0 when it is available. */
		long cooldownSecondsRemaining() {
			long millis = nextSendAtMillis - System.currentTimeMillis();
			return millis <= 0L ? 0L : (millis + 999L) / 1000L;
		}

		/** Minutes the code stays valid, rounded to the nearest minute (at least 1), for the SMS text. */
		long remainingMinutes() {
			long seconds = Math.max(0L, expiresAtMillis - System.currentTimeMillis()) / 1000L;
			return Math.max(1L, (seconds + 30L) / 60L);
		}

		/** Whole minutes (at least 1) until the user may request codes again. */
		long blockedMinutesRemaining() {
			return Math.max(1L, (blockedUntilMillis - System.currentTimeMillis() + 59_999L) / 60_000L);
		}
	}

	enum Verification {
		VALID,
		INVALID,
		/** The code's lifetime is over; the user has to request a new one. */
		EXPIRED,
		/** The user has no code (never sent, discarded after too many guesses, or long expired). */
		NO_CODE
	}

	private final KeycloakSession session;
	private final int length;
	private final int ttl;
	private final int resendLimit;
	private final int resendBlockDuration;
	private final int resendCooldown;

	SmsCode(KeycloakSession session, Map<String, String> config) {
		this.session = session;
		this.length = Math.max(1, intConfig(config, "length", DEFAULT_LENGTH));
		this.ttl = Math.max(1, intConfig(config, "ttl", DEFAULT_TTL));
		this.resendLimit = Math.max(0, intConfig(config, RESEND_LIMIT_CONFIG, DEFAULT_RESEND_LIMIT));
		this.resendBlockDuration = intConfig(config, RESEND_BLOCK_DURATION_CONFIG, DEFAULT_RESEND_BLOCK_DURATION);
		this.resendCooldown = intConfig(config, RESEND_COOLDOWN_CONFIG, DEFAULT_RESEND_COOLDOWN);
	}

	Outcome issue(UserModel user, String recipient) {
		long now = System.currentTimeMillis();
		long blockedUntil = blockedUntil(user);
		if (blockedUntil > now) {
			return Outcome.blocked(blockedUntil);
		}

		Map<String, String> existing = store().get(CODE_KEY + user.getId());
		boolean resent = existing != null;

		if (resendCooldown > 0) {
			// putIfAbsent is atomic across the cluster: exactly one of several concurrent
			// requests gets to send.
			if (!store().putIfAbsent(COOLDOWN_KEY + user.getId(), resendCooldown)) {
				Map<String, String> cooldown = store().get(COOLDOWN_KEY + user.getId());
				long sentAt = cooldown == null ? 0L : parseLongOrZero(cooldown.get(SENT_AT));
				logger.debugf("Ignoring SMS code request of user %s inside the %d s cooldown", user.getUsername(), resendCooldown);
				return Outcome.coolingDown((sentAt > 0L ? sentAt : now) + (resendCooldown * 1000L));
			}
			store().put(COOLDOWN_KEY + user.getId(), resendCooldown, Map.of(SENT_AT, Long.toString(now)));
		}

		// Sends per user within one ttl window, whether they re-send the same code, issue a
		// fresh one or come from separate login attempts.
		Map<String, String> sends = store().get(SENDS_KEY + user.getId());
		long windowStart = sends == null ? 0L : parseLongOrZero(sends.get(WINDOW_START));
		long windowEnd = windowStart + (ttl * 1000L);
		int count = 0;
		if (sends == null || windowEnd <= now) {
			windowStart = now;
			windowEnd = now + (ttl * 1000L);
		} else {
			count = parseIntOrZero(sends.get(COUNT));
		}
		count++;
		// A non-positive block duration disables blocking: codes are then re-sent without limit.
		if (resendBlockDuration > 0 && count > resendLimit + 1) {
			blockedUntil = block(user, now, count - 1);
			store().remove(SENDS_KEY + user.getId());
			return Outcome.blocked(blockedUntil);
		}
		store().put(SENDS_KEY + user.getId(), secondsUntil(windowEnd, now),
			Map.of(COUNT, Integer.toString(count), WINDOW_START, Long.toString(windowStart)));

		String code;
		long expiresAt;
		boolean reusable = existing != null
			&& parseLongOrZero(existing.get(EXPIRES_AT)) - now >= MIN_REMAINING_SECONDS * 1000L
			&& recipient.equals(existing.get(RECIPIENT));
		if (reusable) {
			code = existing.get(CODE);
			expiresAt = parseLongOrZero(existing.get(EXPIRES_AT));
			logger.debugf("Re-sending SMS code of user %s (send %d of %d in this window)", user.getUsername(), count, resendLimit + 1);
		} else {
			code = SecretGenerator.getInstance().randomString(length, SecretGenerator.DIGITS);
			expiresAt = now + (ttl * 1000L);
			store().put(CODE_KEY + user.getId(), ttl + EXPIRED_GRACE_SECONDS,
				Map.of(CODE, code, EXPIRES_AT, Long.toString(expiresAt), RECIPIENT, recipient, ATTEMPTS, "0"));
			logger.debugf("Issuing new SMS code of user %s (%s, send %d of %d in this window)", user.getUsername(),
				resent ? "previous code expired, about to expire or sent elsewhere" : "no current code", count, resendLimit + 1);
		}
		int resendsLeft = Math.max(0, resendLimit + 1 - count);
		// After the last allowed send the page counts down to the end of the window, when
		// sends are possible again, so a button user never runs into the block.
		long nextSendAt = resendsLeft == 0 ? Math.max(windowEnd, now + (resendCooldown * 1000L)) : now + (resendCooldown * 1000L);
		return Outcome.issued(code, expiresAt, nextSendAt, resent, resendsLeft);
	}

	Verification verify(UserModel user, String enteredCode) {
		long now = System.currentTimeMillis();
		String codeKey = CODE_KEY + user.getId();
		Map<String, String> entry = store().get(codeKey);
		if (entry == null) {
			return Verification.NO_CODE;
		}
		long expiresAt = parseLongOrZero(entry.get(EXPIRES_AT));
		if (expiresAt <= now) {
			store().remove(codeKey);
			return Verification.EXPIRED;
		}
		if (!store().putIfAbsent(VERIFY_KEY + user.getId(), VERIFY_INTERVAL_SECONDS)) {
			logger.debugf("Rejecting SMS code verification of user %s: another one ran less than %d s ago",
				user.getUsername(), VERIFY_INTERVAL_SECONDS);
			return Verification.INVALID;
		}

		byte[] expected = entry.get(CODE).getBytes(StandardCharsets.UTF_8);
		byte[] actual = enteredCode == null ? new byte[0] : enteredCode.getBytes(StandardCharsets.UTF_8);
		if (MessageDigest.isEqual(expected, actual)) {
			store().remove(codeKey);
			store().remove(SENDS_KEY + user.getId());
			store().remove(COOLDOWN_KEY + user.getId());
			return Verification.VALID;
		}

		int attempts = parseIntOrZero(entry.get(ATTEMPTS)) + 1;
		if (attempts >= MAX_ATTEMPTS) {
			store().remove(codeKey);
			logger.warnf("Discarding SMS code of user %s after %d wrong guesses", user.getUsername(), attempts);
		} else {
			Map<String, String> updated = new HashMap<>(entry);
			updated.put(ATTEMPTS, Integer.toString(attempts));
			store().put(codeKey, secondsUntil(expiresAt + (EXPIRED_GRACE_SECONDS * 1000L), now), updated);
		}
		return Verification.INVALID;
	}

	/** Epoch millis until which the user is blocked, or 0 when not blocked. */
	private long blockedUntil(UserModel user) {
		Map<String, String> block = store().get(BLOCK_KEY + user.getId());
		return block == null ? 0L : parseLongOrZero(block.get(BLOCKED_UNTIL));
	}

	private long block(UserModel user, long now, int sends) {
		logger.warnf("Blocking SMS code requests of user %s for %d seconds after %d sends within %d seconds",
			user.getUsername(), resendBlockDuration, sends, ttl);
		long until = now + (resendBlockDuration * 1000L);
		store().put(BLOCK_KEY + user.getId(), resendBlockDuration, Map.of(BLOCKED_UNTIL, Long.toString(until)));
		return until;
	}

	private SingleUseObjectProvider store() {
		return session.singleUseObjects();
	}

	private static long secondsUntil(long epochMillis, long now) {
		return Math.max(1L, (epochMillis - now + 999L) / 1000L);
	}

	/** Reads an int option; empty or unparsable values (admin console input) fall back to the default. */
	private static int intConfig(Map<String, String> config, String key, String defaultValue) {
		String value = config.get(key);
		if (value == null || value.isBlank()) {
			return Integer.parseInt(defaultValue);
		}
		try {
			return Integer.parseInt(value.trim());
		} catch (NumberFormatException e) {
			logger.warnf("SMS authenticator option '%s' is not a number ('%s'), using default %s", key, value, defaultValue);
			return Integer.parseInt(defaultValue);
		}
	}

	private static int parseIntOrZero(String value) {
		return value == null || value.isBlank() ? 0 : Integer.parseInt(value);
	}

	private static long parseLongOrZero(String value) {
		return value == null || value.isBlank() ? 0L : Long.parseLong(value);
	}
}
