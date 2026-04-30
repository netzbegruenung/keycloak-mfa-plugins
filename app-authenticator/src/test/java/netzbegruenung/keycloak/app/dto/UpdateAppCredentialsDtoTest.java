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

package netzbegruenung.keycloak.app.dto;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("UpdateAppCredentialsDto")
class UpdateAppCredentialsDtoTest {

	@Nested
	@DisplayName("Creation")
	class Creation {

		@Test
		@DisplayName("should create record with device push ID")
		void shouldCreateRecordWithDevicePushId() {
			String devicePushId = "test-push-token";

			UpdateAppCredentialsDto dto = new UpdateAppCredentialsDto(devicePushId);

			assertThat(dto.devicePushId()).isEqualTo(devicePushId);
		}

		@Test
		@DisplayName("should handle null device push ID")
		void shouldHandleNullDevicePushId() {
			UpdateAppCredentialsDto dto = new UpdateAppCredentialsDto(null);

			assertThat(dto.devicePushId()).isNull();
		}
	}
}
