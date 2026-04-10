package netzbegruenung.keycloak.authenticator;

import com.fasterxml.jackson.databind.ObjectMapper;
import dasniko.testcontainers.keycloak.KeycloakContainer;
import netzbegruenung.keycloak.KeycloakTestContainer;
import netzbegruenung.keycloak.KeycloakTestUtils;
import netzbegruenung.keycloak.PlaywrightContainer;
import org.jboss.logging.Logger;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.representations.idm.RealmRepresentation;
import org.mockserver.client.MockServerClient;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.Network;
import org.testcontainers.mockserver.MockServerContainer;
import org.testcontainers.utility.DockerImageName;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.mockserver.model.HttpRequest.request;
import static org.mockserver.model.HttpResponse.response;

public abstract class AbstractAuthenticatorTest implements KeycloakTestUtils {

	private static final Logger log = Logger.getLogger(AbstractAuthenticatorTest.class);
	public static final ObjectMapper MAPPER = new ObjectMapper();

	private List<String> knownRealms;

	@BeforeEach
	public void setup() {
		knownRealms = new ArrayList<>();
	}

	@AfterEach
	public void cleanupKeycloakInstance() {
		List.copyOf(knownRealms).forEach(realmName -> {
			findRealmByName(realmName).remove();
			knownRealms.remove(realmName);
		});
	}

	protected List<String> getKnownRealms() {
		return List.copyOf(knownRealms);
	}

	private static Network network = Network.newNetwork();

	public static final KeycloakContainer container = new KeycloakTestContainer(network);

	protected static final GenericContainer<?> playwrightContainer = new PlaywrightContainer(network);

	protected static final MockServerContainer mockServer = new MockServerContainer(DockerImageName.parse("mockserver/mockserver:5.15.0"))
		.withNetworkAliases("mockserver")
		.withNetwork(network);

	protected static MockServerClient mockServerClient;

    @BeforeAll
    static void startContainer() {
        container.start();
		playwrightContainer.start();
		mockServer.start();
		mockServerClient = new MockServerClient(mockServer.getHost(), mockServer.getServerPort());

		mockServerClient.when(request().withPath("/sms")).respond(response().withStatusCode(200));
    }

	 @AfterAll
	 public static void tearDown() {
		 mockServerClient.reset();
		 container.stop();
		 playwrightContainer.stop();
		 mockServer.stop();
		 network.close();
	 }

	 private Keycloak keycloak;

	public Keycloak getKeycloak() {
		if (keycloak == null) {
			keycloak = Keycloak.getInstance(container.getAuthServerUrl(), "master", container.getAdminUsername(), container.getAdminPassword(), "admin-cli");
		}
		return keycloak;
	}

	@Override
	public RealmRepresentation createRealm(RealmRepresentation realmRepresentation) {
		final var realm = KeycloakTestUtils.super.createRealm(realmRepresentation);
		knownRealms.add(realmRepresentation.getRealm());
		return realm;
	}

	public static Map<String, String> parseFormData(String formData) {
		Map<String, String> map = new HashMap<>();

		for (String pair : formData.split("&")) {
			int idx = pair.indexOf("=");

			if (idx > 0) {
				String key = pair.substring(0, idx);
				String value = pair.substring(idx + 1);

				// URL decode both key and value
				key = URLDecoder.decode(key, StandardCharsets.UTF_8);
				value = URLDecoder.decode(value, StandardCharsets.UTF_8);

				map.put(key, value);
			}
		}

		return map;
	}

	public static String extractCodeFromBody(String body) {
		Pattern pattern = Pattern.compile("\\b(\\d{6})\\b");
		Matcher matcher = pattern.matcher(body);

		if (matcher.find()) {
			return matcher.group(1);
		}

		throw new IllegalArgumentException("No code found in Body: " + body);
	}

}
