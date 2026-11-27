package netzbegruenung.keycloak.authenticator.vonage;

import org.junit.jupiter.api.Test;

import java.util.Locale;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

class VonageLocalesTest {

	@Test
	void languageAndCountryIsUsedWhenSupported() {
		assertEquals("pt-br", VonageLocales.fromLocale(Locale.forLanguageTag("pt-BR"), false));
		assertEquals("en-gb", VonageLocales.fromLocale(Locale.UK, false));
	}

	@Test
	void languageOnlyIsTriedWithTheCountryOfTheSameName() {
		assertEquals("de-de", VonageLocales.fromLocale(Locale.GERMAN, false));
		assertEquals("fr-fr", VonageLocales.fromLocale(Locale.FRENCH, false));
	}

	@Test
	void unsupportedLocaleIsLeftToVonage() {
		assertNull(VonageLocales.fromLocale(Locale.ENGLISH, false));
		assertNull(VonageLocales.fromLocale(Locale.forLanguageTag("de-AT"), false));
		assertNull(VonageLocales.fromLocale(null, false));
	}

	@Test
	void localeWithoutDefaultTextNeedsCustomTemplate() {
		Locale catalan = Locale.forLanguageTag("ca-ES");
		assertNull(VonageLocales.fromLocale(catalan, false));
		assertEquals("ca-es", VonageLocales.fromLocale(catalan, true));
	}
}
