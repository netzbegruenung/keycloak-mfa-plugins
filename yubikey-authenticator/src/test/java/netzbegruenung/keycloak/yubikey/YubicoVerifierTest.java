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
 *
 * @author Netzbegruenung e.V.
 * @author verdigado eG
 */

package netzbegruenung.keycloak.yubikey;

import org.junit.jupiter.api.Test;

import java.util.Base64;
import java.util.SortedMap;
import java.util.TreeMap;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

class YubicoVerifierTest {

	/**
	 * Official Yubico test vector for the HMAC-SHA1 request/response signature.
	 * https://developers.yubico.com/OTP/Specifications/OTP_validation_protocol.html
	 */
	@Test
	void testOfficialSignatureVector() {
		String secretKeyBase64 = "mG5be6ZJU1qBGz24yPh/ESM3UdU=";
		byte[] apiKeyRaw = Base64.getDecoder().decode(secretKeyBase64);

		SortedMap<String, String> params = new TreeMap<>();
		params.put("id", "1");
		params.put("nonce", "jrFwbaYFhn0HoxZIsd9LQ6w2ceU");
		params.put("otp", "vvungrrdhvtklknvrtvuvbbkeidikkvgglrvdgrfcdft");

		String signature = YubicoVerifier.yubicoSign(apiKeyRaw, params);

		assertEquals("+ja8S3IjbX593/LAgTBixwPNGX4=", signature);
	}

	@Test
	void testStringToSignFormat() {
		SortedMap<String, String> params = new TreeMap<>();
		params.put("otp", "vvungrrdhvtklknvrtvuvbbkeidikkvgglrvdgrfcdft");
		params.put("id", "1");
		params.put("nonce", "jrFwbaYFhn0HoxZIsd9LQ6w2ceU");

		// TreeMap sorts lexicographically by key regardless of insertion order
		String expectedOrder = "id=1&nonce=jrFwbaYFhn0HoxZIsd9LQ6w2ceU&otp=vvungrrdhvtklknvrtvuvbbkeidikkvgglrvdgrfcdft";
		StringBuilder actual = new StringBuilder();
		params.forEach((k, v) -> {
			if (actual.length() > 0) actual.append("&");
			actual.append(k).append("=").append(v);
		});

		assertEquals(expectedOrder, actual.toString());
	}

	@Test
	void testYubikeyPublicId() {
		String otp = "vvungrrdhvtklknvrtvuvbbkeidikkvgglrvdgrfcdft";
		assertEquals("vvungrrdhvtk", YubicoVerifier.yubikeyPublicId(otp));
	}

	@Test
	void testYubikeyPublicIdTooShort() {
		assertNull(YubicoVerifier.yubikeyPublicId("short"));
		assertNull(YubicoVerifier.yubikeyPublicId(null));
	}

	@Test
	void testParseResponse() {
		String body = "h=abc123=\r\n"
			+ "t=2024-01-01T00:00:00Z0000\r\n"
			+ "otp=vvungrrdhvtklknvrtvuvbbkeidikkvgglrvdgrfcdft\r\n"
			+ "nonce=jrFwbaYFhn0HoxZIsd9LQ6w2ceU\r\n"
			+ "sl=100\r\n"
			+ "status=OK\r\n";

		SortedMap<String, String> parsed = YubicoVerifier.parseResponse(body);

		assertEquals("abc123=", parsed.get("h"));
		assertEquals("OK", parsed.get("status"));
		assertEquals("jrFwbaYFhn0HoxZIsd9LQ6w2ceU", parsed.get("nonce"));
		assertEquals("vvungrrdhvtklknvrtvuvbbkeidikkvgglrvdgrfcdft", parsed.get("otp"));
	}
}
