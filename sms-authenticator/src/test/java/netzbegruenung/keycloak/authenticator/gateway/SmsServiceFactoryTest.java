package netzbegruenung.keycloak.authenticator.gateway;

import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.keycloak.models.KeycloakSession;
import org.keycloak.vault.VaultStringSecret;
import org.keycloak.vault.VaultTranscriber;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class SmsServiceFactoryTest {

	private HttpServer server;
	private final LinkedBlockingQueue<String> authorizations = new LinkedBlockingQueue<>();
	private KeycloakSession session;
	private VaultTranscriber vault;

	@BeforeEach
	void setUp() throws IOException {
		server = HttpServer.create(new InetSocketAddress("localhost", 0), 0);
		server.createContext("/sms", exchange -> {
			String authorization = exchange.getRequestHeaders().getFirst("Authorization");
			authorizations.add(authorization == null ? "<none>" : authorization);
			exchange.sendResponseHeaders(200, -1);
			exchange.close();
		});
		server.start();
		session = mock(KeycloakSession.class);
		vault = mock(VaultTranscriber.class);
		when(session.vault()).thenReturn(vault);
	}

	@AfterEach
	void tearDown() {
		server.stop(0);
	}

	private Map<String, String> gatewayConfig() {
		Map<String, String> config = new HashMap<>();
		config.put("apiurl", "http://localhost:" + server.getAddress().getPort() + "/sms");
		config.put("urlencode", "true");
		config.put("messageattribute", "body");
		config.put("receiverattribute", "to");
		config.put("senderattribute", "sender");
		config.put("senderId", "test-sender");
		config.put("apiTokenInHeader", "true");
		return config;
	}

	private static VaultStringSecret secret(Optional<String> value) {
		VaultStringSecret secret = mock(VaultStringSecret.class);
		when(secret.get()).thenReturn(value);
		return secret;
	}

	private String awaitAuthorization() throws InterruptedException {
		String authorization = authorizations.poll(5, TimeUnit.SECONDS);
		assertTrue(authorization != null, "Expected the SMS gateway stub to receive a request");
		return authorization;
	}

	@Test
	@DisplayName("Simulation mode logs the SMS text (its only purpose) with the number masked")
	void simulationLogsTheTextWithTheNumberMasked() {
		List<String> lines;
		try (LogCapture logs = new LogCapture()) {
			SmsServiceFactory.get(Map.of("simulation", "true")).send("+491234567", "Your SMS code is 123456");
			lines = logs.lines();
		}
		assertEquals(1, lines.size(), "Expected one simulation log line: " + lines);
		assertTrue(lines.get(0).contains("+*****4567"), lines.get(0));
		assertTrue(lines.get(0).contains("Your SMS code is 123456"), lines.get(0));
		assertFalse(lines.get(0).contains("+491234567"), lines.get(0));
	}

	@Test
	@DisplayName("A vault reference in apitoken is resolved before the SMS is sent")
	void vaultReferenceIsResolved() throws Exception {
		Map<String, String> config = gatewayConfig();
		config.put("apitoken", "${vault.sms-token}");
		VaultStringSecret resolved = secret(Optional.of("real-token"));
		when(vault.getStringSecret("${vault.sms-token}")).thenReturn(resolved);

		SmsServiceFactory.get(config, session).send("+491234567", "code");

		assertEquals("real-token", awaitAuthorization());
	}

	@Test
	@DisplayName("A vault reference whose key is missing is sent as written")
	void missingVaultKeyKeepsTheReference() throws Exception {
		Map<String, String> config = gatewayConfig();
		config.put("apitoken", "${vault.missing}");
		VaultStringSecret missing = secret(Optional.empty());
		when(vault.getStringSecret("${vault.missing}")).thenReturn(missing);

		SmsServiceFactory.get(config, session).send("+491234567", "code");

		assertEquals("${vault.missing}", awaitAuthorization());
	}

	@Test
	@DisplayName("An empty apitoken and an absent apiuser are not looked up in the vault")
	void emptyOrAbsentCredentialsAreNotLookedUp() throws Exception {
		Map<String, String> config = gatewayConfig();
		config.put("apiTokenInHeader", "false");
		config.put("apitoken", "");

		SmsServiceFactory.get(config, session).send("+491234567", "code");

		assertEquals("<none>", awaitAuthorization());
		verify(vault, never()).getStringSecret(anyString());
	}

	@Test
	@DisplayName("Without a session, the configuration is used as is")
	void withoutSessionTheConfigIsUsedAsIs() throws Exception {
		Map<String, String> config = gatewayConfig();
		config.put("apitoken", "${vault.sms-token}");

		SmsServiceFactory.get(config, null).send("+491234567", "code");

		assertEquals("${vault.sms-token}", awaitAuthorization());
	}
}
