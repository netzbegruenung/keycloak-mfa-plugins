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

import static org.junit.jupiter.api.Assertions.assertEquals;

@DisplayName("ChallengeDto")
class ChallengeDtoTest {

	@Nested
	@DisplayName("Creation")
	class Creation {

		@Test
		@DisplayName("should create record with all fields")
		void shouldCreateRecordWithAllFields() {
			String userName = "testuser";
			String userFirstName = "Test";
			String userLastName = "User";
			String targetUrl = "https://example.com/token";
			String codeChallenge = "secret123";
			Long updatedTimestamp = 1234567890L;
			String ipAddress = "192.168.1.1";
			String device = "TestDevice";
			String browser = "Chrome";
			String os = "Android";
			String osVersion = "12";
			String clientName = "Test Client";
			String clientUrl = "https://example.com";
			String loginId = "login-123";

			ChallengeDto dto = new ChallengeDto(
				userName, userFirstName, userLastName, targetUrl, codeChallenge,
				updatedTimestamp, ipAddress, device, browser, os, osVersion,
				clientName, clientUrl, loginId
			);

			assertEquals(userName, dto.userName());
			assertEquals(userFirstName, dto.userFirstName());
			assertEquals(userLastName, dto.userLastName());
			assertEquals(targetUrl, dto.targetUrl());
			assertEquals(codeChallenge, dto.codeChallenge());
			assertEquals(updatedTimestamp, dto.updatedTimestamp());
			assertEquals(ipAddress, dto.ipAddress());
			assertEquals(device, dto.device());
			assertEquals(browser, dto.browser());
			assertEquals(os, dto.os());
			assertEquals(osVersion, dto.osVersion());
			assertEquals(clientName, dto.clientName());
			assertEquals(clientUrl, dto.clientUrl());
			assertEquals(loginId, dto.loginId());
		}
	}
}