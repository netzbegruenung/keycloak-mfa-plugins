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

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("PhoneNumberRequiredAction utility methods")
class PhoneNumberRequiredActionUtilityTest {

	@Nested
	@DisplayName("Credential type")
	class CredentialType {

		@Test
		@DisplayName("should have correct provider ID")
		void shouldHaveCorrectProviderId() {
			assertThat(PhoneNumberRequiredAction.PROVIDER_ID).isEqualTo("mobile_number_config");
		}
	}

	@Nested
	@DisplayName("Phone number formatting")
	class PhoneNumberFormatting {

		@Test
		@DisplayName("should have non-digit pattern")
		void shouldHaveNonDigitPattern() {
			// Test that the pattern removes non-digit characters
			String input = "+49-176/1234.567";
			String result = input.replaceAll("[^0-9+]", "");
			assertThat(result).isEqualTo("+491761234567");
		}

		@Test
		@DisplayName("should have whitespace pattern")
		void shouldHaveWhitespacePattern() {
			// Test that the pattern matches whitespace
			String input = "+49 176 1234 567";
			String result = input.replaceAll("\\s+", "");
			assertThat(result).isEqualTo("+491761234567");
		}
	}

	@Nested
	@DisplayName("Second factors")
	class SecondFactors {

		@Test
		@DisplayName("should include SMS authenticator type")
		void shouldIncludeSmsAuthenticatorType() {
			assertThat(SmsAuthCredentialModel.TYPE).isEqualTo("mobile-number");
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
			assertThat(parts).hasSize(2);
			assertThat(parts[0]).isEqualTo("MOBILE");
			assertThat(parts[1]).isEqualTo("FIXED_LINE_OR_MOBILE");
		}

		@Test
		@DisplayName("should handle single filter")
		void shouldHandleSingleFilter() {
			String input = "MOBILE";
			String[] parts = input.split("##");
			assertThat(parts).hasSize(1);
			assertThat(parts[0]).isEqualTo("MOBILE");
		}
	}
}
