package netzbegruenung.keycloak.authenticator.vonage;

import netzbegruenung.keycloak.authenticator.verification.SmsVerificationException;
import netzbegruenung.keycloak.authenticator.verification.SmsVerificationResult;

import org.jboss.logging.Logger;
import org.keycloak.util.JsonSerialization;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The two calls of the Vonage Verify v2 API that are needed for an SMS verification, see
 * https://developer.vonage.com/en/api/verify.v2
 */
class VonageVerifyClient {

	private static final Logger logger = Logger.getLogger(VonageVerifyClient.class);
	private static final HttpClient HTTP_CLIENT = HttpClient.newBuilder()
		.connectTimeout(Duration.ofSeconds(5))
		.build();
	private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(10);

	private final String verifyUrl;
	private final String authorization;

	VonageVerifyClient(String baseUrl, String apiKey, String apiSecret) {
		this.verifyUrl = baseUrl.replaceAll("/+$", "") + "/v2/verify";
		this.authorization = "Basic " + Base64.getEncoder()
			.encodeToString((apiKey + ":" + apiSecret).getBytes(StandardCharsets.UTF_8));
	}

	/**
	 * Start a verification with a single SMS step.
	 *
	 * @param to             the phone number in E.164 format without the leading +
	 * @param channelTimeout seconds until the SMS step times out
	 * @param locale         a Vonage locale like en-us, or null to let Vonage choose from the phone number
	 * @param templateId     the id of a custom template, or null for the default text
	 * @return the id of the verification request
	 */
	String start(String to, String brand, int codeLength, int channelTimeout, String locale, String templateId)
			throws SmsVerificationException {
		Map<String, Object> body = new LinkedHashMap<>();
		body.put("brand", brand);
		body.put("code_length", codeLength);
		body.put("channel_timeout", channelTimeout);
		if (locale != null) {
			body.put("locale", locale);
		}
		if (templateId != null) {
			body.put("template_id", templateId);
		}
		body.put("workflow", List.of(Map.of("channel", "sms", "to", to)));

		HttpResponse<String> response;
		try {
			response = post(verifyUrl, body);
		} catch (IOException e) {
			throw new SmsVerificationException("Failed to call Vonage Verify", e);
		}

		if (response.statusCode() != 202) {
			throw new SmsVerificationException(
				"Vonage Verify did not start the verification: " + describe(response));
		}
		Object requestId;
		try {
			requestId = JsonSerialization.readValue(response.body(), Map.class).get("request_id");
		} catch (IOException e) {
			throw new SmsVerificationException("Failed to read the response of Vonage Verify", e);
		}
		if (!(requestId instanceof String) || ((String) requestId).isBlank()) {
			throw new SmsVerificationException("Vonage Verify did not return a request_id");
		}
		return (String) requestId;
	}

	/**
	 * Ask Vonage if the code is correct. A request accepts a wrong code three times, after
	 * that it is terminated.
	 */
	SmsVerificationResult check(String requestId, String code) {
		HttpResponse<String> response;
		try {
			response = post(verifyUrl + "/" + URLEncoder.encode(requestId, StandardCharsets.UTF_8), Map.of("code", code));
		} catch (IOException e) {
			logger.errorf(e, "Failed to call Vonage Verify for request %s", requestId);
			return SmsVerificationResult.ERROR;
		}

		switch (response.statusCode()) {
			case 200:
				return SmsVerificationResult.VALID;
			case 400:
				// the code does not match
				return SmsVerificationResult.INVALID;
			case 404:
				// the request is not known (anymore), it has timed out or was completed
			case 410:
				// a wrong code was entered too many times, the request is terminated
				logger.infof("Vonage Verify request %s can no longer be used: %s", requestId, describe(response));
				return SmsVerificationResult.EXPIRED;
			default:
				logger.errorf("Vonage Verify could not check the code for request %s: %s", requestId, describe(response));
				return SmsVerificationResult.ERROR;
		}
	}

	private HttpResponse<String> post(String url, Map<String, Object> body) throws IOException {
		HttpRequest request = HttpRequest.newBuilder()
			.uri(URI.create(url))
			.timeout(REQUEST_TIMEOUT)
			.header("Authorization", authorization)
			.header("Content-Type", "application/json")
			.header("Accept", "application/json")
			.POST(HttpRequest.BodyPublishers.ofString(JsonSerialization.writeValueAsString(body)))
			.build();
		try {
			return HTTP_CLIENT.send(request, HttpResponse.BodyHandlers.ofString());
		} catch (InterruptedException e) {
			Thread.currentThread().interrupt();
			throw new IOException("Interrupted while waiting for Vonage Verify", e);
		}
	}

	/** Status plus the title and detail of the error, which do not contain the code or the phone number. */
	private static String describe(HttpResponse<String> response) {
		String description = "status " + response.statusCode();
		try {
			Map<?, ?> error = JsonSerialization.readValue(response.body(), Map.class);
			if (error.get("title") != null) {
				description += ", " + error.get("title");
			}
			if (error.get("detail") != null) {
				description += ": " + error.get("detail");
			}
		} catch (Exception e) {
			// no error body to describe
		}
		return description;
	}
}
