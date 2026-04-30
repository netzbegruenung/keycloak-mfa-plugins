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

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("ApiSmsService")
class ApiSmsServiceTest {

	private Map<String, String> config;

	@BeforeEach
	void setUp() {
		config = new HashMap<>();
		config.put("apiurl", "https://example.com/api/sms/send");
		config.put("senderId", "TestSender");
		config.put("messageattribute", "text");
		config.put("receiverattribute", "to");
		config.put("senderattribute", "from");
		config.put("countrycode", "+49");
	}

	private java.lang.reflect.Method getCleanPhoneNumberMethod() {
		try {
			java.lang.reflect.Method method = ApiSmsService.class.getDeclaredMethod(
				"cleanPhoneNumber", String.class, String.class
			);
			method.setAccessible(true);
			return method;
		} catch (NoSuchMethodException e) {
			throw new RuntimeException(e);
		}
	}

	private java.lang.reflect.Method getGetJsonBodyMethod() {
		try {
			java.lang.reflect.Method method = ApiSmsService.class.getDeclaredMethod(
				"getJsonBody", String.class, String.class
			);
			method.setAccessible(true);
			return method;
		} catch (NoSuchMethodException e) {
			throw new RuntimeException(e);
		}
	}

	private String invokeCleanMethod(ApiSmsService service, java.lang.reflect.Method method, String phone, String country) {
		try {
			return (String) method.invoke(service, phone, country);
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	private String invokeGetJsonBodyMethod(ApiSmsService service, java.lang.reflect.Method method, String phone, String message) {
		try {
			return (String) method.invoke(service, phone, message);
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	@Nested
	@DisplayName("Phone number cleaning")
	class PhoneNumberCleaning {

		@Test
		@DisplayName("should convert 0049 to +49")
		void shouldConvert0049ToPlus49() {
			ApiSmsService service = new ApiSmsService(config);
			java.lang.reflect.Method cleanMethod = getCleanPhoneNumberMethod();
			String result = invokeCleanMethod(service, cleanMethod, "00491761234567", "+49");
			assertEquals("+491761234567", result);
		}

		@Test
		@DisplayName("should convert 49 to +49")
		void shouldConvert49ToPlus49() {
			ApiSmsService service = new ApiSmsService(config);
			java.lang.reflect.Method cleanMethod = getCleanPhoneNumberMethod();
			String result = invokeCleanMethod(service, cleanMethod, "491761234567", "+49");
			assertEquals("+491761234567", result);
		}

		@Test
		@DisplayName("should convert +490176 to +49176")
		void shouldConvertPlus490176ToPlus49176() {
			ApiSmsService service = new ApiSmsService(config);
			java.lang.reflect.Method cleanMethod = getCleanPhoneNumberMethod();
			String result = invokeCleanMethod(service, cleanMethod, "+4901761234567", "+49");
			assertEquals("+491761234567", result);
		}

		@Test
		@DisplayName("should convert leading 0 to +49")
		void shouldConvertLeading0ToPlus49() {
			ApiSmsService service = new ApiSmsService(config);
			java.lang.reflect.Method cleanMethod = getCleanPhoneNumberMethod();
			String result = invokeCleanMethod(service, cleanMethod, "01761234567", "+49");
			assertEquals("+491761234567", result);
		}

		@Test
		@DisplayName("should return phone number unchanged if country code is empty")
		void shouldReturnPhoneNumberUnchangedIfCountryCodeIsEmpty() {
			config.put("countrycode", "");
			ApiSmsService service = new ApiSmsService(config);
			java.lang.reflect.Method cleanMethod = getCleanPhoneNumberMethod();
			String result = invokeCleanMethod(service, cleanMethod, "01761234567", "");
			assertEquals("01761234567", result);
		}

		@Test
		@DisplayName("should return phone number unchanged if country code is null")
		void shouldReturnPhoneNumberUnchangedIfCountryCodeIsNull() {
			config.remove("countrycode");
			ApiSmsService service = new ApiSmsService(config);
			java.lang.reflect.Method cleanMethod = getCleanPhoneNumberMethod();
			String result = invokeCleanMethod(service, cleanMethod, "01761234567", null);
			assertEquals("01761234567", result);
		}
	}

	@Nested
	@DisplayName("JSON body generation")
	class JsonBodyGeneration {

		@Test
		@DisplayName("should generate default JSON body")
		void shouldGenerateDefaultJsonBody() {
			ApiSmsService service = new ApiSmsService(config);
			java.lang.reflect.Method getJsonMethod = getGetJsonBodyMethod();
			String result = invokeGetJsonBodyMethod(service, getJsonMethod, "+491761234567", "Test message");
			assertTrue(result.contains("\"text\":\"Test message\""));
			assertTrue(result.contains("\"to\":\"+491761234567\""));
			assertTrue(result.contains("\"from\":\"TestSender\""));
		}

		@Test
		@DisplayName("should generate JSON body with custom template")
		void shouldGenerateJsonBodyWithCustomTemplate() {
			config.put("jsonTemplate", "{\"custom_phone\":\"%s\",\"custom_msg\":\"%s\"}");
			ApiSmsService service = new ApiSmsService(config);
			java.lang.reflect.Method getJsonMethod = getGetJsonBodyMethod();
			String result = invokeGetJsonBodyMethod(service, getJsonMethod, "+491761234567", "Test message");
			assertEquals("{\"custom_phone\":\"+491761234567\",\"custom_msg\":\"Test message\"}", result);
		}
	}
}