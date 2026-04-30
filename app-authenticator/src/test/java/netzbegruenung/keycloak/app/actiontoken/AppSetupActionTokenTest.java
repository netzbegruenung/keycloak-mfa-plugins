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

package netzbegruenung.keycloak.app.actiontoken;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("AppSetupActionToken")
class AppSetupActionTokenTest {

	@Nested
	@DisplayName("Token type")
	class TokenType {

		@Test
		@DisplayName("should have correct token type")
		void shouldHaveCorrectTokenType() {
			assertThat(AppSetupActionToken.TOKEN_TYPE).isEqualTo("app-setup-action-token");
		}
	}

	@Nested
	@DisplayName("Creation")
	class Creation {

		@Test
		@DisplayName("should create token with correct values")
		void shouldCreateTokenWithCorrectValues() {
			String userId = "user-123";
			Integer expiration = 3600;
			String authSessionId = "auth-session-456";
			String clientId = "client-789";

			AppSetupActionToken token = new AppSetupActionToken(userId, expiration, authSessionId, clientId);

			assertThat(token.getUserId()).isEqualTo(userId);
			//assertThat(token.get  getAbsoluteExpirationInSecs()).isEqualTo(expiration);
			assertThat(token.getOriginalAuthenticationSessionId()).isEqualTo(authSessionId);
			assertThat(token.getIssuer()).isEqualTo(clientId);
			assertThat(token.getType()).isEqualTo(AppSetupActionToken.TOKEN_TYPE);
		}
	}
}
