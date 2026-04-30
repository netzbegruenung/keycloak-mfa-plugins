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

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("PhoneValidationRequiredAction utility methods")
class PhoneValidationRequiredActionUtilityTest {

	@Nested
	@DisplayName("Provider identification")
	class ProviderIdentification {

		@Test
		@DisplayName("should have correct provider ID")
		void shouldHaveCorrectProviderId() {
			assertThat(PhoneValidationRequiredAction.PROVIDER_ID).isEqualTo("phone_validation_config");
		}
	}

	@Nested
	@DisplayName("SmsAuthenticator constants")
	class SmsAuthenticatorConstants {

		@Test
		@DisplayName("should have correct TPL_CODE constant")
		void shouldHaveCorrectTplCodeConstant() {
			assertThat(SmsAuthenticator.TPL_CODE).isEqualTo("login-sms.ftl");
		}
	}
}
