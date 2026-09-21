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

import org.jboss.logging.Logger;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.Base64;
import java.util.Map;
import java.util.SortedMap;
import java.util.TreeMap;
import java.util.stream.Collectors;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Client for the Yubico OTP Validation Protocol v2.0 (see
 * https://developers.yubico.com/OTP/Specifications/OTP_validation_protocol.html).
 *
 * This class never stores or logs the plaintext secret key.
 */
public final class YubicoVerifier {

	private static final Logger logger = Logger.getLogger(YubicoVerifier.class);

	private static final char[] NONCE_CHARS =
		"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789".toCharArray();

	private static final Duration CONNECT_TIMEOUT = Duration.ofSeconds(10);
	private static final Duration READ_TIMEOUT = Duration.ofSeconds(10);

	public enum Result {
		OK,
		BAD_OTP,
		REPLAYED,
		BAD_SIGNATURE,
		NETWORK_ERROR,
		OTHER
	}

	private final String validationUrl;
	private final String clientId;
	private final byte[] secretKeyRaw;

	public YubicoVerifier(String validationUrl, String clientId, String secretKeyBase64) {
		this.validationUrl = validationUrl;
		this.clientId = clientId;
		this.secretKeyRaw = Base64.getDecoder().decode(secretKeyBase64);
	}

	/**
	 * Extracts the 12-character public id (the key's stable identity) from a full
	 * 44-character YubiKey OTP string.
	 *
	 * @return the 12-char public id, or null if the OTP is too short
	 */
	public static String yubikeyPublicId(String otp) {
		if (otp == null || otp.length() < 12) {
			return null;
		}
		return otp.substring(0, 12);
	}

	static String randomNonce() {
		SecureRandom rng = new SecureRandom();
		StringBuilder sb = new StringBuilder(32);
		for (int i = 0; i < 32; i++) {
			sb.append(NONCE_CHARS[rng.nextInt(NONCE_CHARS.length)]);
		}
		return sb.toString();
	}

	/**
	 * Computes the HMAC-SHA1 request/response signature over the given params,
	 * sorted lexicographically by key, joined as "key=value" pairs with "&amp;"
	 * (no URL-encoding), then Base64-encoded using standard (non URL-safe) Base64.
	 */
	static String yubicoSign(byte[] apiKeyRaw, SortedMap<String, String> params) {
		String line = params.entrySet().stream()
			.map(e -> e.getKey() + "=" + e.getValue())
			.collect(Collectors.joining("&"));
		try {
			Mac mac = Mac.getInstance("HmacSHA1");
			mac.init(new SecretKeySpec(apiKeyRaw, "HmacSHA1"));
			byte[] sig = mac.doFinal(line.getBytes(StandardCharsets.UTF_8));
			return Base64.getEncoder().encodeToString(sig);
		} catch (GeneralSecurityException e) {
			throw new RuntimeException(e);
		}
	}

	/**
	 * Parses a Yubico validation server response body (one "key=value" per line,
	 * CRLF or LF separated) into a sorted map.
	 */
	static SortedMap<String, String> parseResponse(String body) {
		SortedMap<String, String> result = new TreeMap<>();
		if (body == null) {
			return result;
		}
		for (String rawLine : body.split("\r\n|\n")) {
			String line = rawLine.trim();
			if (line.isEmpty()) {
				continue;
			}
			int idx = line.indexOf('=');
			if (idx < 0) {
				continue;
			}
			result.put(line.substring(0, idx), line.substring(idx + 1));
		}
		return result;
	}

	/**
	 * Runs the full protocol against the configured validation server: signs the
	 * request, performs the HTTP GET, then verifies the response signature, nonce
	 * echo, OTP echo, and status.
	 */
	public Result verify(String otp) {
		String nonce = randomNonce();

		SortedMap<String, String> requestParams = new TreeMap<>();
		requestParams.put("id", clientId);
		requestParams.put("nonce", nonce);
		requestParams.put("otp", otp);

		String signature = yubicoSign(secretKeyRaw, requestParams);

		String query = requestParams.entrySet().stream()
			.map(e -> e.getKey() + "=" + java.net.URLEncoder.encode(e.getValue(), StandardCharsets.UTF_8))
			.collect(Collectors.joining("&"))
			+ "&h=" + java.net.URLEncoder.encode(signature, StandardCharsets.UTF_8);

		String body;
		try {
			HttpClient client = HttpClient.newBuilder()
				.connectTimeout(CONNECT_TIMEOUT)
				.build();
			HttpRequest request = HttpRequest.newBuilder()
				.uri(URI.create(validationUrl + "?" + query))
				.timeout(READ_TIMEOUT)
				.GET()
				.build();
			HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
			body = response.body();
		} catch (Exception e) {
			logger.warnf(e, "YubicoVerifier: network error contacting validation server");
			return Result.NETWORK_ERROR;
		}

		SortedMap<String, String> responseParams = parseResponse(body);
		String receivedSignature = responseParams.remove("h");

		if (receivedSignature == null) {
			logger.error("YubicoVerifier: response missing signature");
			return Result.BAD_SIGNATURE;
		}

		String expectedSignature = yubicoSign(secretKeyRaw, responseParams);
		if (!expectedSignature.equals(receivedSignature)) {
			logger.error("YubicoVerifier: response signature mismatch");
			return Result.BAD_SIGNATURE;
		}

		if (!nonce.equals(responseParams.get("nonce"))) {
			logger.error("YubicoVerifier: response nonce mismatch");
			return Result.BAD_SIGNATURE;
		}

		if (!otp.equals(responseParams.get("otp"))) {
			logger.error("YubicoVerifier: response otp mismatch");
			return Result.BAD_SIGNATURE;
		}

		String status = responseParams.get("status");
		if ("OK".equals(status)) {
			return Result.OK;
		}

		logger.warnf("YubicoVerifier: validation failed with status %s", status);
		if ("REPLAYED_OTP".equals(status) || "REPLAYED_REQUEST".equals(status)) {
			return Result.REPLAYED;
		}
		if ("BAD_OTP".equals(status)) {
			return Result.BAD_OTP;
		}
		if ("BAD_SIGNATURE".equals(status)) {
			return Result.BAD_SIGNATURE;
		}
		return Result.OTHER;
	}
}
