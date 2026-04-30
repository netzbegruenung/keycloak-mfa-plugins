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

package netzbegruenung.keycloak.authenticator.credentials;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("SmsAuthCredentialData")
class SmsAuthCredentialDataTest {

	@Test
	@DisplayName("should store mobile number")
	void shouldStoreMobileNumber() {
		String mobileNumber = "+491761234567";
		SmsAuthCredentialData data = new SmsAuthCredentialData(mobileNumber);

		assertThat(data.getMobileNumber()).isEqualTo(mobileNumber);
	}

	@Test
	@DisplayName("should store empty mobile number")
	void shouldStoreEmptyMobileNumber() {
		String mobileNumber = "";
		SmsAuthCredentialData data = new SmsAuthCredentialData(mobileNumber);

		assertThat(data.getMobileNumber()).isEmpty();
	}

	@Test
	@DisplayName("should store null mobile number")
	void shouldStoreNullMobileNumber() {
		SmsAuthCredentialData data = new SmsAuthCredentialData(null);

		assertThat(data.getMobileNumber()).isNull();
	}
}
