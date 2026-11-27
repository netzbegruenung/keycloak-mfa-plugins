package netzbegruenung.keycloak.authenticator.gateway;

import com.sun.net.httpserver.Headers;
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
import java.util.List;
import java.util.Map;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * ApiSmsService.send() talks to the configured "apiurl" via plain java.net.http.HttpClient
 * and has no Keycloak-runtime dependency, so it's exercised here with a local HttpServer
 * stub instead of a full Keycloak/browser integration test.
 */
class ApiSmsServiceTest {

	private HttpServer server;
	private final LinkedBlockingQueue<CapturedRequest> requests = new LinkedBlockingQueue<>();

	private record CapturedRequest(String method, String uri, Headers headers, String body) {
		String contentType() {
			return headers.getFirst("Content-Type");
		}

		String authorization() {
			return headers.getFirst("Authorization");
		}
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
				exchange.getRequestMethod(),
				exchange.getRequestURI().toString(),
				exchange.getRequestHeaders(),
				body
			));
			exchange.sendResponseHeaders(200, -1);
			exchange.close();
		});
		server.createContext("/fail", exchange -> {
			exchange.sendResponseHeaders(500, -1);
			exchange.close();
		});
		server.createContext("/talkative", exchange -> {
			byte[] response = "gateway-response-body".getBytes(StandardCharsets.UTF_8);
			exchange.sendResponseHeaders(200, response.length);
			exchange.getResponseBody().write(response);
			exchange.close();
		});
		server.start();
	}

	private String serverUrl(String path) {
		return "http://localhost:" + server.getAddress().getPort() + path;
	}

	/** Like newService, but the overrides may contain null values (a key present with no value). */
	private ApiSmsService newServiceWithNulls(Map<String, String> overrides) {
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

	private static Map<String, String> withNull(String key, String... keyValues) {
		Map<String, String> map = new HashMap<>();
		map.put(key, null);
		for (int i = 0; i < keyValues.length; i += 2) {
			map.put(keyValues[i], keyValues[i + 1]);
		}
		return map;
	}

	@AfterEach
	void stopServer() {
		server.stop(0);
	}

	private String apiUrl() {
		return "http://localhost:" + server.getAddress().getPort() + "/sms";
	}

	private String failUrl() {
		return "http://localhost:" + server.getAddress().getPort() + "/fail";
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

	@Test
	@DisplayName("Formatting characters are stripped even when no countrycode is configured")
	void stripsFormattingCharactersWithoutCountryCode() throws Exception {
		ApiSmsService service = newService(Map.of("urlencode", "true", "countrycode", ""));

		service.send("+49 (0176) 123-456", "code");

		assertEquals("+490176123456", parseFormData(awaitRequest().body()).get("to"));
	}

	@Test
	@DisplayName("stripFormattingCharacters defaults to enabled when the option is absent from the config")
	void stripsFormattingCharactersByDefault() throws Exception {
		Map<String, String> config = new HashMap<>();
		config.put("apiurl", apiUrl());
		config.put("messageattribute", "body");
		config.put("receiverattribute", "to");
		config.put("senderattribute", "sender");
		config.put("senderId", "test-sender");
		config.put("countrycode", "");
		config.put("urlencode", "true");
		ApiSmsService service = new ApiSmsService(config);

		service.send("+49 176 123 456", "code");

		assertEquals("+49176123456", parseFormData(awaitRequest().body()).get("to"));
	}

	@Test
	@DisplayName("stripFormattingCharacters=false leaves the number untouched")
	void keepsFormattingCharactersWhenDisabled() throws Exception {
		ApiSmsService service = newService(Map.of(
			"urlencode", "true",
			"countrycode", "",
			"stripFormattingCharacters", "false"
		));

		service.send("+49 (0176) 123-456", "code");

		assertEquals("+49 (0176) 123-456", parseFormData(awaitRequest().body()).get("to"));
	}

	@Test
	@DisplayName("stripFormattingCharacters=false does not disable the country prefix normalisation")
	void keepsCountryCodeNormalisationWhenStrippingDisabled() throws Exception {
		ApiSmsService service = newService(Map.of(
			"urlencode", "true",
			"countrycode", "+49",
			"stripFormattingCharacters", "false"
		));

		service.send("0176 123 456", "code");

		// PhoneNumberNormalizer ignores the spaces on its own when a countrycode is configured
		assertEquals("+49176123456", parseFormData(awaitRequest().body()).get("to"));
	}

	@Test
	@DisplayName("Non-breaking spaces are stripped as well")
	void stripsNonBreakingSpaces() throws Exception {
		ApiSmsService service = newService(Map.of("urlencode", "true", "countrycode", ""));

		service.send("+49 176 123456", "code");

		assertEquals("+49176123456", parseFormData(awaitRequest().body()).get("to"));
	}

	@Test
	@DisplayName("A spaced number is stripped before the country prefix is applied")
	void stripsFormattingCharactersBeforeCountryCodeNormalisation() throws Exception {
		ApiSmsService service = newService(Map.of("urlencode", "true", "countrycode", "+49"));

		service.send("0049 176 123 456", "code");

		assertEquals("+49176123456", parseFormData(awaitRequest().body()).get("to"));
	}

	@Test
	@DisplayName("Formatting characters are stripped in JSON mode too")
	void stripsFormattingCharactersInJsonMode() throws Exception {
		ApiSmsService service = newService(Map.of("urlencode", "false", "countrycode", ""));

		service.send("+49 176 123 456", "code");

		assertTrue(awaitRequest().body().contains("\"to\":\"+49176123456\""));
	}

	@Test
	@DisplayName("stripPlusPrefix still applies after formatting characters are removed")
	void stripsFormattingCharactersBeforeStrippingPlusPrefix() throws Exception {
		ApiSmsService service = newService(Map.of(
			"urlencode", "true",
			"countrycode", "",
			"stripPlusPrefix", "true"
		));

		service.send("+49 176 123 456", "code");

		assertEquals("49176123456", parseFormData(awaitRequest().body()).get("to"));
	}

	@Test
	@DisplayName("cleanPhoneNumber: 0043... with default +49 is normalised to +43...")
	void cleanPhoneNumberKeepsForeignCountryCodeAfterInternationalPrefix() throws Exception {
		ApiSmsService service = newService(Map.of("urlencode", "true", "countrycode", "+49"));

		service.send("00436641234567", "code");

		assertEquals("+436641234567", parseFormData(awaitRequest().body()).get("to"));
	}

	@Test
	@DisplayName("cleanPhoneNumber: national number without trunk prefix gets the default country code")
	void cleanPhoneNumberAddsCountryCodeWithoutTrunkPrefix() throws Exception {
		ApiSmsService service = newService(Map.of("urlencode", "true", "countrycode", "+1"));

		service.send("2025550123", "code");

		assertEquals("+12025550123", parseFormData(awaitRequest().body()).get("to"));
	}

	@Test
	@DisplayName("cleanPhoneNumber: stripPlusPrefix is applied after normalisation")
	void cleanPhoneNumberWithStripPlusPrefix() throws Exception {
		ApiSmsService service = newService(Map.of("urlencode", "true", "countrycode", "+43", "stripPlusPrefix", "true"));

		service.send("06641234567", "code");

		assertEquals("436641234567", parseFormData(awaitRequest().body()).get("to"));
	}

	@Test
	@DisplayName("No log line contains the full phone number: success, stripped formatting, HTTP error, network error")
	void logLinesNeverContainTheFullNumber() throws Exception {
		List<String> lines;
		try (LogCapture logs = new LogCapture()) {
			newService(Map.of("urlencode", "true", "countrycode", "")).send("+49 176 123456", "code");
			awaitRequest();
			newService(Map.of("urlencode", "true", "countrycode", "", "apiurl", failUrl())).send("+49176123456", "code");
			newService(Map.of("urlencode", "true", "countrycode", "", "apiurl", "http://localhost:1/sms"))
				.send("+49176123456", "code");
			lines = logs.lines();
		}
		assertTrue(lines.stream().anyMatch(line -> line.contains("+*******3456")),
			"Expected the masked number in the log lines: " + lines);
		assertTrue(lines.stream().noneMatch(line -> line.contains("49176123456") || line.contains("+49 176 123456")),
			"A log line contains the full number: " + lines);
	}

	@Test
	@DisplayName("GET mode: error logs leak neither the number nor the code through the request URL")
	void getModeErrorLogsDoNotLeakThroughTheUrl() {
		List<String> lines;
		try (LogCapture logs = new LogCapture()) {
			newService(Map.of("countrycode", "", "apiurl", failUrl(), "getUrl", "/{phone}?text={message}"))
				.send("+49176123456", "your code is 123456");
			newService(Map.of("countrycode", "", "apiurl", "http://localhost:1/sms", "getUrl", "/{phone}?text={message}"))
				.send("+49176123456", "your code is 123456");
			lines = logs.lines();
		}
		assertEquals(2, lines.stream().filter(line -> line.startsWith("Failed to send message")).count(),
			"Expected the HTTP error and the network error to be logged: " + lines);
		assertTrue(lines.stream().noneMatch(line -> line.contains("49176123456") || line.contains("123456")),
			"A log line contains the number or the code: " + lines);
	}

	@Test
	@DisplayName("stripPlusPrefix leaves a number without + alone")
	void stripPlusPrefixLeavesNumbersWithoutPlusAlone() throws Exception {
		newService(Map.of("urlencode", "true", "stripPlusPrefix", "true")).send("0176123456", "code");

		assertEquals("0176123456", parseFormData(awaitRequest().body()).get("to"));
	}

	@Test
	@DisplayName("A getUrl key without value falls back to a POST request")
	void nullGetUrlFallsBackToPost() throws Exception {
		newServiceWithNulls(withNull("getUrl", "urlencode", "true")).send("+491234567", "code");

		CapturedRequest request = awaitRequest();
		assertEquals("POST", request.method());
		assertEquals("+491234567", parseFormData(request.body()).get("to"));
	}

	@Test
	@DisplayName("apiTokenInHeader with a token attribute sends the token in that header")
	void apiTokenInHeaderUsesTheConfiguredHeaderName() throws Exception {
		newService(Map.of(
			"urlencode", "false",
			"apiTokenInHeader", "true",
			"apitokenattribute", "X-API-Key",
			"apitoken", "my-raw-token"
		)).send("+491234567", "code");

		CapturedRequest request = awaitRequest();
		assertEquals("my-raw-token", request.headers().getFirst("X-API-Key"));
		assertNull(request.authorization());
	}

	@Test
	@DisplayName("apiTokenInHeader with a token attribute key without value uses the Authorization header")
	void apiTokenInHeaderWithoutAttributeValueUsesAuthorization() throws Exception {
		newServiceWithNulls(withNull("apitokenattribute", "urlencode", "false", "apiTokenInHeader", "true",
			"apitoken", "my-raw-token")).send("+491234567", "code");

		assertEquals("my-raw-token", awaitRequest().authorization());
	}

	@Test
	@DisplayName("An API user sends HTTP Basic credentials")
	void apiUserSendsBasicCredentials() throws Exception {
		newService(Map.of("urlencode", "true", "apiuser", "user", "apitoken", "pass")).send("+491234567", "code");

		assertEquals("Basic dXNlcjpwYXNz", awaitRequest().authorization());
	}

	@Test
	@DisplayName("An apiuser key without value sends no credentials")
	void apiUserWithoutValueSendsNoCredentials() throws Exception {
		newServiceWithNulls(withNull("apiuser", "urlencode", "true")).send("+491234567", "code");

		assertNull(awaitRequest().authorization());
	}

	@Test
	@DisplayName("hideResponsePayload keeps the gateway's response out of the log")
	void hideResponsePayloadRedactsTheResponse() {
		List<String> lines;
		try (LogCapture logs = new LogCapture()) {
			newService(Map.of("urlencode", "true", "apiurl", serverUrl("/talkative"), "hideResponsePayload", "true"))
				.send("+491234567", "code");
			lines = logs.lines();
		}
		assertTrue(lines.stream().anyMatch(line -> line.startsWith("Sent SMS to") && line.contains("[redacted]")),
			"Expected a redacted success line: " + lines);
		assertTrue(lines.stream().noneMatch(line -> line.contains("gateway-response-body")), lines.toString());
	}

	@Test
	@DisplayName("The gateway's response is logged when hideResponsePayload is off")
	void responsePayloadIsLoggedByDefault() {
		List<String> lines;
		try (LogCapture logs = new LogCapture()) {
			newService(Map.of("urlencode", "true", "apiurl", serverUrl("/talkative"))).send("+491234567", "code");
			lines = logs.lines();
		}
		assertTrue(lines.stream().anyMatch(line -> line.contains("[Response: gateway-response-body]")), lines.toString());
	}

	@Test
	@DisplayName("An invalid apiurl is logged with a null request, and nothing is thrown")
	void invalidApiUrlIsLoggedWithNullRequest() {
		List<String> lines;
		try (LogCapture logs = new LogCapture()) {
			newService(Map.of("urlencode", "true", "apiurl", "http://bad host/sms")).send("+491234567", "code");
			lines = logs.lines();
		}
		assertTrue(lines.stream().anyMatch(line -> line.endsWith("with request: null. Validate your config.")),
			lines.toString());
	}

	@Test
	@DisplayName("A server without explicit port is logged as method and host only")
	void serverWithoutPortIsLoggedWithoutPort() {
		List<String> lines;
		try (LogCapture logs = new LogCapture()) {
			newService(Map.of("urlencode", "true", "apiurl", "http://localhost/sms")).send("+491234567", "code");
			lines = logs.lines();
		}
		assertTrue(lines.stream().anyMatch(line -> line.contains("with request: POST http://localhost.")),
			lines.toString());
	}

	@Test
	@DisplayName("A JSON template receives the number and the message")
	void jsonTemplateReceivesNumberAndMessage() throws Exception {
		newService(Map.of("urlencode", "false", "jsonTemplate", "{\"n\":\"%s\",\"m\":\"%s\"}"))
			.send("+491234567", "code 42");

		assertEquals("{\"n\":\"+491234567\",\"m\":\"code 42\"}", awaitRequest().body());
	}

	@Test
	@DisplayName("A JSON template with useUuid receives a UUID first")
	void jsonTemplateWithUuidReceivesUuidFirst() throws Exception {
		newService(Map.of("urlencode", "false", "useUuid", "true",
			"jsonTemplate", "{\"id\":\"%s\",\"n\":\"%s\",\"m\":\"%s\"}")).send("+491234567", "code 42");

		assertTrue(awaitRequest().body().matches(
			"\\{\"id\":\"[0-9a-f-]{36}\",\"n\":\"\\+491234567\",\"m\":\"code 42\"}"));
	}

	@Test
	@DisplayName("JSON mode puts the token in the body when it is not sent as a header")
	void jsonBodyCarriesTheTokenWhenNotInHeader() throws Exception {
		newService(Map.of("urlencode", "false", "apitokenattribute", "token", "apitoken", "t0k"))
			.send("+491234567", "code");

		assertTrue(awaitRequest().body().startsWith("{\"token\":\"t0k\",\"body\":\"code\""));
	}

	@Test
	@DisplayName("JSON mode with token and UUID puts both first, comma separated")
	void jsonBodyCarriesTokenThenUuid() throws Exception {
		newService(Map.of("urlencode", "false", "apitokenattribute", "token", "apitoken", "t0k",
			"useUuid", "true", "uuidAttribute", "id")).send("+491234567", "code");

		assertTrue(awaitRequest().body().matches(
			"\\{\"token\":\"t0k\",\"id\":\"[0-9a-f-]{36}\",\"body\":\"code\",.*"));
	}

	@Test
	@DisplayName("JSON mode with a UUID only starts with the UUID")
	void jsonBodyStartsWithTheUuid() throws Exception {
		newService(Map.of("urlencode", "false", "useUuid", "true", "uuidAttribute", "id")).send("+491234567", "code");

		assertTrue(awaitRequest().body().matches("\\{\"id\":\"[0-9a-f-]{36}\",\"body\":\"code\",.*"));
	}

	@Test
	@DisplayName("JSON mode with a token attribute key without value sends no token")
	void jsonBodyWithoutTokenAttributeValue() throws Exception {
		newServiceWithNulls(withNull("apitokenattribute", "urlencode", "false", "apitoken", "t0k"))
			.send("+491234567", "code");

		assertTrue(awaitRequest().body().startsWith("{\"body\":\"code\""));
	}

	@Test
	@DisplayName("urlencoded mode leaves the token out of the body when it is sent as a header")
	void urlencodedBodyOmitsTheTokenSentAsHeader() throws Exception {
		newService(Map.of("urlencode", "true", "apiTokenInHeader", "true", "apitokenattribute", "token",
			"apitoken", "t0k")).send("+491234567", "code");

		CapturedRequest request = awaitRequest();
		assertFalse(parseFormData(request.body()).containsKey("token"));
		assertEquals("t0k", request.headers().getFirst("token"));
	}

	@Test
	@DisplayName("urlencoded mode carries a UUID when useUuid is set")
	void urlencodedBodyCarriesTheUuid() throws Exception {
		newService(Map.of("urlencode", "true", "useUuid", "true", "uuidAttribute", "id")).send("+491234567", "code");

		assertTrue(parseFormData(awaitRequest().body()).get("id").matches("[0-9a-f-]{36}"));
	}

	@Test
	@DisplayName("GET mode fills the placeholders, with an empty sender when senderId has no value")
	void getModeFillsThePlaceholders() throws Exception {
		newServiceWithNulls(withNull("senderId", "getUrl", "?to={phone}&text={message}&key={apitoken}&from={senderId}",
			"apitoken", "t0k")).send("+491234567", "code 42");

		CapturedRequest request = awaitRequest();
		assertEquals("GET", request.method());
		assertEquals("/sms?to=%2B491234567&text=code+42&key=t0k&from=", request.uri());
	}

	@Test
	@DisplayName("A null number is not sent: the failure is logged, nothing is thrown")
	void nullNumberIsLoggedAsAFailure() {
		List<String> lines;
		try (LogCapture logs = new LogCapture()) {
			newService(Map.of("urlencode", "true")).send(null, "code");
			lines = logs.lines();
		}
		assertTrue(lines.stream().anyMatch(line -> line.startsWith("Failed to send message to null")), lines.toString());
		assertTrue(requests.isEmpty());
	}
}
