package netzbegruenung.keycloak.authenticator.gateway;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

class PhoneNumberMaskerTest {

	@Test
	void nullStaysNull() {
		assertNull(PhoneNumberMasker.mask(null));
	}

	@Test
	void keepsPlusAndLastFour() {
		assertEquals("+*****4567", PhoneNumberMasker.mask("+491234567"));
	}

	@Test
	void withoutPlusKeepsLastFour() {
		assertEquals("******5678", PhoneNumberMasker.mask("0612345678"));
	}

	@Test
	void fourOrFewerCharactersAreFullyMasked() {
		assertEquals("****", PhoneNumberMasker.mask("1234"));
	}

	@Test
	void shortNumberWithPlusKeepsOnlyThePlus() {
		assertEquals("+***", PhoneNumberMasker.mask("+123"));
	}
}
