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

package netzbegruenung.keycloak.authenticator.gateway;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertInstanceOf;


@DisplayName("SmsServiceFactory")
class SmsServiceFactoryTest {

	@Test
	@DisplayName("should return simulated service when simulation mode is enabled")
	void shouldReturnSimulatedServiceWhenSimulationModeIsEnabled() {
		Map<String, String> config = new HashMap<>();
		config.put("simulation", "true");

		SmsService service = SmsServiceFactory.get(config);

		// Simulated service should not throw exception when sending
		service.send("+491761234567", "Test message");
	}

	@Test
	@DisplayName("should return ApiSmsService when simulation mode is disabled")
	void shouldReturnApiSmsServiceWhenSimulationModeIsDisabled() {
		Map<String, String> config = new HashMap<>();
		config.put("simulation", "false");
		config.put("apiurl", "https://example.com/api");
		config.put("senderId", "Test");
		config.put("messageattribute", "text");
		config.put("receiverattribute", "to");
		config.put("senderattribute", "from");

		SmsService service = SmsServiceFactory.get(config);

		assertInstanceOf(ApiSmsService.class, service);
	}

	@Test
	@DisplayName("should return simulated service by default when simulation is not specified")
	void shouldReturnSimulatedServiceByDefaultWhenSimulationIsNotSpecified() {
		Map<String, String> config = new HashMap<>();

		SmsService service = SmsServiceFactory.get(config);

		// Default should be simulation mode
		service.send("+491761234567", "Test message");
	}
}
