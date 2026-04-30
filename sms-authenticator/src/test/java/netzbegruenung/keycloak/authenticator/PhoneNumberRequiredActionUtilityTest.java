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
 */

package netzbegruenung.keycloak.authenticator;

import netzbegruenung.keycloak.authenticator.credentials.SmsAuthCredentialModel;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

@DisplayName("PhoneNumberRequiredAction utility methods")
class PhoneNumberRequiredActionUtilityTest {

	@Nested
	@DisplayName("Credential type")
	class CredentialType {

		@Test
		@DisplayName("should have correct provider ID")
		void shouldHaveCorrectProviderId() {
			assertEquals("mobile_number_config", PhoneNumberRequiredAction.PROVIDER_ID);
		}
	}

	@Nested
	@DisplayName("Phone number formatting")
	class PhoneNumberFormatting {

		@Test
		@DisplayName("should have non-digit pattern")
		void shouldHaveNonDigitPattern() {
			String input = "+49-176/1234.567";
			String result = input.replaceAll("[^0-9+]", "");
			assertEquals("+491761234567", result);
		}

		@Test
		@DisplayName("should have whitespace pattern")
		void shouldHaveWhitespacePattern() {
			String input = "+49 176 1234 567";
			String result = input.replaceAll("\\s+", "");
			assertEquals("+491761234567", result);
		}
	}

	@Nested
	@DisplayName("Second factors")
	class SecondFactors {

		@Test
		@DisplayName("should include SMS authenticator type")
		void shouldIncludeSmsAuthenticatorType() {
			assertEquals("mobile-number", SmsAuthCredentialModel.TYPE);
		}
	}

	@Nested
	@DisplayName("Number filter splitter")
	class NumberFilterSplitter {

		@Test
		@DisplayName("should split number filters by ##")
		void shouldSplitNumberFiltersByDoubleHash() {
			String input = "MOBILE##FIXED_LINE_OR_MOBILE";
			String[] parts = input.split("##");
			assertEquals(2, parts.length);
			assertEquals("MOBILE", parts[0]);
			assertEquals("FIXED_LINE_OR_MOBILE", parts[1]);
		}

		@Test
		@DisplayName("should handle single filter")
		void shouldHandleSingleFilter() {
			String input = "MOBILE";
			String[] parts = input.split("##");
			assertEquals(1, parts.length);
			assertEquals("MOBILE", parts[0]);
		}
	}
}
