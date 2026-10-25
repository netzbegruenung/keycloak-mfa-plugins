/*
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
 * @author Netzbegruenung e.V.
 * @author verdigado eG
 */

package netzbegruenung.keycloak.authenticator.gateway;

import com.google.i18n.phonenumbers.NumberParseException;
import com.google.i18n.phonenumbers.PhoneNumberUtil;
import org.jboss.logging.Logger;

import java.util.regex.Pattern;

/**
 * Corrects phone numbers to E.164 before an SMS is sent, using libphonenumber so that the trunk prefix and
 * international dialing prefix rules of the default country are applied (not only the German ones).
 */
final class PhoneNumberNormalizer {

	private static final Logger logger = Logger.getLogger(PhoneNumberNormalizer.class);
	private static final Pattern nonDigitPattern = Pattern.compile("[^0-9]");

	private PhoneNumberNormalizer() {}

	/**
	 * @param phoneNumber        the stored phone number
	 * @param defaultCountryCode the configured default country prefix, e.g. "+49"
	 * @return the number in E.164 format, or the unchanged number if no default country code is configured
	 *         or the number cannot be parsed
	 */
	static String toE164(String phoneNumber, String defaultCountryCode) {
		/*
		 * If there is no default country prefix, this function does not dare to touch the phone number.
		 */
		if (phoneNumber == null || defaultCountryCode == null || defaultCountryCode.isBlank()) {
			logger.infof("Clean phone number: no country code set, return %s", phoneNumber);
			return phoneNumber;
		}

		String countryNumber = nonDigitPattern.matcher(defaultCountryCode).replaceAll("");
		PhoneNumberUtil phoneNumberUtil = PhoneNumberUtil.getInstance();
		String region;
		try {
			region = phoneNumberUtil.getRegionCodeForCountryCode(Integer.parseInt(countryNumber));
		} catch (NumberFormatException e) {
			logger.warnf("Clean phone number: invalid country code %s, return %s", defaultCountryCode, phoneNumber);
			return phoneNumber;
		}
		if (!phoneNumberUtil.getSupportedRegions().contains(region)) {
			logger.warnf("Clean phone number: unknown country code %s, return %s", defaultCountryCode, phoneNumber);
			return phoneNumber;
		}

		// convert 49176... to +49176..., libphonenumber would read it as a national number (+4949176...)
		String candidate = phoneNumber.strip();
		if (candidate.startsWith(countryNumber)) {
			candidate = "+" + candidate;
		}

		try {
			String formatted = phoneNumberUtil.format(
				phoneNumberUtil.parse(candidate, region),
				PhoneNumberUtil.PhoneNumberFormat.E164
			);
			logger.infof("Clean phone number: set phone number %s to %s", phoneNumber, formatted);
			return formatted;
		} catch (NumberParseException e) {
			logger.warnf("Clean phone number: failed to parse %s (%s), return it unchanged", phoneNumber, e.getMessage());
			return phoneNumber;
		}
	}
}
