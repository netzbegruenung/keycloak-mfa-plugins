package netzbegruenung.keycloak.authenticator.gateway;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import static org.junit.jupiter.api.Assertions.assertEquals;

class PhoneNumberNormalizerTest {

	@ParameterizedTest(name = "[{0}] {1} -> {2}")
	@DisplayName("toE164 applies the dialing rules of the default country")
	@CsvSource({
		// German rules, same result as the previous hand-written correction
		"+49, +4917612345678,   +4917612345678",
		"+49, 017612345678,     +4917612345678",
		"+49, 004917612345678,  +4917612345678",
		"+49, 4917612345678,    +4917612345678",
		"+49, 49176123456,      +49176123456",
		"+49, +49017612345678,  +4917612345678",
		// national number without trunk prefix gets the default country code
		"+49, 17612345678,      +4917612345678",
		// international dialing prefix of the default country followed by a foreign country code
		"+49, 00436641234567,   +436641234567",
		"+43, 004917612345678,  +4917612345678",
		"+1,  011447911123456,  +447911123456",
		// countries without a 0 trunk prefix
		"+1,  2025550123,       +12025550123",
		"+39, 3123456789,       +393123456789",
		// the leading 0 of Italian landline numbers is part of the number
		"+39, +390612345678,    +390612345678",
		"+39, 0612345678,       +390612345678",
		// other countries with a 0 trunk prefix
		"+43, 06641234567,      +436641234567",
		"+33, 0612345678,       +33612345678",
		"+44, 07911123456,      +447911123456",
		// default country code configured without +
		"49,  017612345678,     +4917612345678",
	})
	void toE164(String defaultCountryCode, String phoneNumber, String expected) {
		assertEquals(expected, PhoneNumberNormalizer.toE164(phoneNumber, defaultCountryCode));
	}

	@ParameterizedTest(name = "[{0}] {1} stays unchanged")
	@DisplayName("toE164 returns the number unchanged if it cannot be corrected")
	@CsvSource({
		// no default country code configured
		"'',   0176123456",
		// unknown country code
		"+999, 0176123456",
		"abc,  0176123456",
		// not parseable as a phone number
		"+49,  +43+436641234567",
		"+49,  1",
	})
	void toE164Unchanged(String defaultCountryCode, String phoneNumber) {
		assertEquals(phoneNumber, PhoneNumberNormalizer.toE164(phoneNumber, defaultCountryCode));
	}
}
