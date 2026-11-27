package netzbegruenung.keycloak.authenticator.vonage;

import java.util.Locale;
import java.util.Set;

/**
 * Maps a Keycloak locale to a locale of Vonage Verify, see
 * https://developer.vonage.com/en/verify/guides/verify-v2-languages
 */
final class VonageLocales {

	/** Locales Vonage has a default SMS text for. */
	private static final Set<String> WITH_DEFAULT_TEXT = Set.of(
		"ar-xa", "zh-hk", "zh-cn", "zh-tw", "cs-cz", "da-dk", "nl-nl", "en-au", "en-in", "en-gb", "en-us",
		"fil-ph", "fi-fi", "fr-ca", "fr-fr", "de-de", "el-gr", "he-il", "hi-in", "hu-hu", "is-is", "id-id",
		"it-it", "ja-jp", "ko-kr", "nb-no", "pl-pl", "pt-br", "pt-pt", "ro-ro", "ru-ru", "es-mx", "es-es",
		"es-us", "sv-se", "th-th", "tr-tr", "vi-vn", "cy-gb", "yue-cn");

	/** Locales that can only be used with a custom template. */
	private static final Set<String> CUSTOM_TEMPLATE_ONLY = Set.of(
		"af-za", "sq-al", "az-az", "bn-bd", "bg-bg", "ca-es", "cmn-cn", "hr-hr", "et-ee", "ka-ge", "gu-in",
		"ha-ng", "kn-in", "kk-kz", "rw-rw", "ky-kg", "lo-la", "lv-lv", "lt-lt", "ma-mk", "ms-my", "ml-in",
		"mr-in", "pa-in", "sr-ba", "sk-sk", "sl-si", "sw-ke", "ta-in", "te-in", "uk-ua", "ur-pk", "uz-uz",
		"cy-cy", "zu-za");

	private VonageLocales() {
	}

	/**
	 * @return the Vonage locale for the user's locale, or null if there is none. Without a
	 *         locale Vonage chooses the language from the country of the phone number.
	 */
	static String fromLocale(Locale locale, boolean customTemplate) {
		if (locale == null || locale.getLanguage().isEmpty()) {
			return null;
		}
		String language = locale.getLanguage().toLowerCase(Locale.ROOT);
		// "de" is tried as "de-de", which works for the languages named like their main country
		String country = locale.getCountry().isEmpty() ? language : locale.getCountry().toLowerCase(Locale.ROOT);
		String candidate = language + "-" + country;
		if (WITH_DEFAULT_TEXT.contains(candidate) || (customTemplate && CUSTOM_TEMPLATE_ONLY.contains(candidate))) {
			return candidate;
		}
		return null;
	}
}
