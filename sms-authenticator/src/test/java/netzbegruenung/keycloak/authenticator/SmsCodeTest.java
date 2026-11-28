package netzbegruenung.keycloak.authenticator;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.SingleUseObjectProvider;
import org.keycloak.models.UserModel;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Unit tests for the SmsCode branches the browser flow tests cannot reach: races in the store, stale entries,
 * disabled blocking, blank values. The SingleUseObjectProvider is an in-memory map that ignores lifespans.
 */
class SmsCodeTest {

	private static final String USER_ID = "user-1";
	private static final String CODE_KEY = "sms-authenticator.code." + USER_ID;
	private static final String SENDS_KEY = "sms-authenticator.sends." + USER_ID;
	private static final String COOLDOWN_KEY = "sms-authenticator.cooldown." + USER_ID;

	private final Map<String, Map<String, String>> entries = new HashMap<>();
	private SingleUseObjectProvider store;
	private KeycloakSession session;
	private UserModel user;

	@BeforeEach
	void setUp() {
		store = InMemorySingleUseObjects.backedBy(entries);
		session = mock(KeycloakSession.class);
		when(session.singleUseObjects()).thenReturn(store);
		user = mock(UserModel.class);
		when(user.getId()).thenReturn(USER_ID);
		when(user.getUsername()).thenReturn("alice");
	}

	private SmsCode smsCode(String... keyValues) {
		Map<String, String> config = new HashMap<>();
		for (int i = 0; i < keyValues.length; i += 2) {
			config.put(keyValues[i], keyValues[i + 1]);
		}
		return new SmsCode(session, config);
	}

	private static Map<String, String> entry(String... keyValues) {
		Map<String, String> map = new HashMap<>();
		for (int i = 0; i < keyValues.length; i += 2) {
			map.put(keyValues[i], keyValues[i + 1]);
		}
		return map;
	}

	@Test
	@DisplayName("A blocked outcome is not a cooldown")
	void blockedOutcomeIsNotCoolingDown() {
		assertFalse(SmsCode.Outcome.blocked(System.currentTimeMillis() + 60_000L).coolingDown());
	}

	@Test
	@DisplayName("A cooldown entry without start time counts the cooldown from now")
	void cooldownWithoutStartTimeCountsFromNow() {
		entries.put(COOLDOWN_KEY, entry());
		long before = System.currentTimeMillis();

		SmsCode.Outcome outcome = smsCode().issue(user, "+491234567");

		assertTrue(outcome.coolingDown());
		assertTrue(outcome.nextSendAtMillis() >= before + 60_000L);
	}

	@Test
	@DisplayName("A cooldown that expires between the two store calls still answers 'cooling down'")
	void cooldownVanishingMeanwhileStillCoolsDown() {
		when(store.putIfAbsent(eq(COOLDOWN_KEY), anyLong())).thenReturn(false);
		long before = System.currentTimeMillis();

		SmsCode.Outcome outcome = smsCode().issue(user, "+491234567");

		assertTrue(outcome.coolingDown());
		assertTrue(outcome.nextSendAtMillis() >= before + 60_000L);
	}

	@Test
	@DisplayName("A send window that is over but still stored starts a new window")
	void staleWindowStartsANewOne() {
		long longAgo = System.currentTimeMillis() - 400_000L;
		entries.put(SENDS_KEY, entry("count", "4", "windowStart", Long.toString(longAgo)));

		SmsCode.Outcome outcome = smsCode("resendCooldown", "0").issue(user, "+491234567");

		assertNotNull(outcome.code());
		assertEquals(4, outcome.resendsLeft());
		assertEquals("1", entries.get(SENDS_KEY).get("count"));
	}

	@Test
	@DisplayName("A non-positive block duration disables the block")
	void zeroBlockDurationNeverBlocks() {
		SmsCode smsCode = smsCode("resendCooldown", "0", "resendLimit", "0", "resendBlockDuration", "0");

		for (int send = 0; send < 5; send++) {
			assertFalse(smsCode.issue(user, "+491234567").blocked(), "send " + send);
		}
	}

	@Test
	@DisplayName("A second verification within a second is rejected without counting an attempt")
	void verificationsWithinOneSecondAreThrottled() {
		SmsCode smsCode = smsCode("resendCooldown", "0");
		smsCode.issue(user, "+491234567");

		assertEquals(SmsCode.Verification.INVALID, smsCode.verify(user, "wrong"));
		assertEquals(SmsCode.Verification.INVALID, smsCode.verify(user, "wrong-again"));

		assertEquals("1", entries.get(CODE_KEY).get("attempts"));
	}

	@Test
	@DisplayName("Blank options fall back to the defaults")
	void blankOptionsFallBackToDefaults() {
		SmsCode.Outcome outcome = smsCode("length", " ", "resendCooldown", "0").issue(user, "+491234567");

		assertEquals(6, outcome.code().length());
	}

	@Test
	@DisplayName("A blank send count is read as no send yet")
	void blankSendCountReadsAsZero() {
		entries.put(SENDS_KEY, entry("count", "", "windowStart", Long.toString(System.currentTimeMillis())));

		smsCode("resendCooldown", "0").issue(user, "+491234567");

		assertEquals("1", entries.get(SENDS_KEY).get("count"));
	}

	@Test
	@DisplayName("A code entry with a blank expiry is expired")
	void blankExpiryIsExpired() {
		entries.put(CODE_KEY, entry("code", "123456", "expiresAt", "", "attempts", "0"));

		assertEquals(SmsCode.Verification.EXPIRED, smsCode().verify(user, "123456"));
	}

	@Test
	@DisplayName("Missing or blank attempt counters are read as no attempt yet")
	void missingOrBlankAttemptsReadAsZero() {
		String expiresAt = Long.toString(System.currentTimeMillis() + 300_000L);
		entries.put(CODE_KEY, entry("code", "123456", "expiresAt", expiresAt));
		assertEquals(SmsCode.Verification.INVALID, smsCode().verify(user, "000000"));
		assertEquals("1", entries.get(CODE_KEY).get("attempts"));

		entries.remove("sms-authenticator.verify." + USER_ID);
		entries.put(CODE_KEY, entry("code", "123456", "expiresAt", expiresAt, "attempts", ""));
		assertEquals(SmsCode.Verification.INVALID, smsCode().verify(user, "000000"));
		assertEquals("1", entries.get(CODE_KEY).get("attempts"));
	}
}
