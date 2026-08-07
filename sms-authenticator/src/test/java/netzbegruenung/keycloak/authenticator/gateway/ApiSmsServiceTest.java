package netzbegruenung.keycloak.authenticator.gateway;

import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * ApiSmsService.send() talks to the configured "apiurl" via plain java.net.http.HttpClient
 * and has no Keycloak-runtime dependency, so it's exercised here with a local HttpServer
 * stub instead of a full Keycloak/browser integration test.
 */
class ApiSmsServiceTest {

	private HttpServer server;
	private final LinkedBlockingQueue<CapturedRequest> requests = new LinkedBlockingQueue<>();

	private record CapturedRequest(String contentType, String authorization, String body) {
	}

	@BeforeEach
	void startServer() throws IOException {
		server = HttpServer.create(new InetSocketAddress("localhost", 0), 0);
		server.createContext("/sms", exchange -> {
			String body;
			try (InputStream is = exchange.getRequestBody()) {
				body = new String(is.readAllBytes(), StandardCharsets.UTF_8);
			}
			requests.add(new CapturedRequest(
				exchange.getRequestHeaders().getFirst("Content-Type"),
				exchange.getRequestHeaders().getFirst("Authorization"),
				body
			));
			exchange.sendResponseHeaders(200, -1);
			exchange.close();
		});
		server.start();
	}

	@AfterEach
	void stopServer() {
		server.stop(0);
	}

	private String apiUrl() {
		return "http://localhost:" + server.getAddress().getPort() + "/sms";
	}

	private CapturedRequest awaitRequest() throws InterruptedException {
		CapturedRequest request = requests.poll(5, TimeUnit.SECONDS);
		assertNotNull(request, "Expected the SMS gateway stub to receive a request");
		return request;
	}

	private ApiSmsService newService(Map<String, String> overrides) {
		Map<String, String> config = new HashMap<>();
		config.put("apiurl", apiUrl());
		config.put("messageattribute", "body");
		config.put("receiverattribute", "to");
		config.put("senderattribute", "sender");
		config.put("senderId", "test-sender");
		config.put("countrycode", "");
		config.putAll(overrides);
		return new ApiSmsService(config);
	}

	private static Map<String, String> parseFormData(String body) {
		Map<String, String> result = new HashMap<>();
		for (String pair : body.split("&")) {
			int idx = pair.indexOf('=');
			if (idx > 0) {
				String key = URLDecoder.decode(pair.substring(0, idx), StandardCharsets.UTF_8);
				String value = URLDecoder.decode(pair.substring(idx + 1), StandardCharsets.UTF_8);
				result.put(key, value);
			}
		}
		return result;
	}

	@Test
	@DisplayName("JSON mode sends a JSON body with the configured field names")
	void jsonModeSendsJsonBody() throws Exception {
		ApiSmsService service = newService(Map.of("urlencode", "false"));

		service.send("+491234567", "your code is 123456");

		CapturedRequest request = awaitRequest();
		assertEquals("application/json", request.contentType());
		assertTrue(request.body().contains("\"body\":\"your code is 123456\""));
		assertTrue(request.body().contains("\"to\":\"+491234567\""));
		assertTrue(request.body().contains("\"sender\":\"test-sender\""));
	}

	@Test
	@DisplayName("urlencoded mode sends a form-encoded body with the configured field names")
	void urlencodedModeSendsFormBody() throws Exception {
		ApiSmsService service = newService(Map.of("urlencode", "true"));

		service.send("+491234567", "your code is 123456");

		CapturedRequest request = awaitRequest();
		assertEquals("application/x-www-form-urlencoded", request.contentType());
		Map<String, String> form = parseFormData(request.body());
		assertEquals("your code is 123456", form.get("body"));
		assertEquals("+491234567", form.get("to"));
		assertEquals("test-sender", form.get("sender"));
	}

	@Test
	@DisplayName("apiTokenInHeader sends the raw token as the Authorization header value")
	void apiTokenInHeaderSendsRawToken() throws Exception {
		ApiSmsService service = newService(Map.of(
			"urlencode", "false",
			"apiTokenInHeader", "true",
			"apitoken", "my-raw-token"
		));

		service.send("+491234567", "code");

		CapturedRequest request = awaitRequest();
		assertEquals("my-raw-token", request.authorization());
	}

	@Test
	@DisplayName("cleanPhoneNumber: no transformation when countrycode is empty")
	void cleanPhoneNumberDoesNothingWithoutCountryCode() throws Exception {
		ApiSmsService service = newService(Map.of("urlencode", "true", "countrycode", ""));

		service.send("0176123456", "code");

		assertEquals("0176123456", parseFormData(awaitRequest().body()).get("to"));
	}

	@Test
	@DisplayName("cleanPhoneNumber: 49... is normalised to +49...")
	void cleanPhoneNumberAddsPlusPrefixToNumberStartingWithCountryCode() throws Exception {
		ApiSmsService service = newService(Map.of("urlencode", "true", "countrycode", "+49"));

		service.send("49176123456", "code");

		assertEquals("+49176123456", parseFormData(awaitRequest().body()).get("to"));
	}

	@Test
	@DisplayName("cleanPhoneNumber: 0049... is normalised to +49...")
	void cleanPhoneNumberReplacesDoubleZeroPrefixWithPlus() throws Exception {
		ApiSmsService service = newService(Map.of("urlencode", "true", "countrycode", "+49"));

		service.send("0049176123456", "code");

		assertEquals("+49176123456", parseFormData(awaitRequest().body()).get("to"));
	}

	@Test
	@DisplayName("cleanPhoneNumber: 0... is normalised to +49... (national format with leading 0)")
	void cleanPhoneNumberReplacesLeadingZeroWithCountryCode() throws Exception {
		ApiSmsService service = newService(Map.of("urlencode", "true", "countrycode", "+49"));

		service.send("0176123456", "code");

		assertEquals("+49176123456", parseFormData(awaitRequest().body()).get("to"));
	}
}
