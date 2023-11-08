package netzbegruenung.keycloak.app.rest;

import netzbegruenung.keycloak.dev.AuthorizationServerApp;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.keycloak.common.Profile;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.AutoConfigureTestEntityManager;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.jdbc.Sql;
import org.springframework.test.context.jdbc.SqlConfig;
import org.springframework.test.web.reactive.server.WebTestClient;

import static org.springframework.test.context.jdbc.Sql.ExecutionPhase.AFTER_TEST_METHOD;
import static org.springframework.test.context.jdbc.SqlConfig.TransactionMode.ISOLATED;

@SpringBootTest(classes = {AuthorizationServerApp.class}, webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureTestEntityManager
@ActiveProfiles("test")
@Sql(scripts = {"/import-challenges.sql"},
	config = @SqlConfig(transactionMode = ISOLATED))
@Sql(
	scripts = "/delete-challenges.sql",
	config = @SqlConfig(transactionMode = ISOLATED),
	executionPhase = AFTER_TEST_METHOD
)
public class ChallengeResourceTest {

	private final static String CHALLENGE_URI = "/realms/baeldung/challenges";

	private final static String SIGNATURE_HEADER_NAME = "Signature";

	private final static String SIGNATURE_HEADER_VALUE = "keyId:deviceId,created:%d,signature:base64encodedSignature";

	private final static Long HALF_HOUR_MILLIS = 1800000L;

	@Autowired
	private WebTestClient webClient;

	@BeforeAll
	public static void initProfile() throws Exception {
		Profile profile = Profile.configure();
		Profile.init(profile.getName(), profile.getFeatures());
	}

	@Test
	void testSignatureHeaderRejected() {
		webClient
			.get().uri(CHALLENGE_URI)
			.exchange()
			.expectStatus().isBadRequest()
			.expectBody()
			.jsonPath("$['error']").isEqualTo(ChallengeResource.CHALLENGE_REJECTED)
			.jsonPath("$['message']").hasJsonPath();
	}

	@Test
	void testEmptyChallenges() {
		webClient
			.get().uri(CHALLENGE_URI)
			.header(SIGNATURE_HEADER_NAME, String.format(SIGNATURE_HEADER_VALUE, System.currentTimeMillis()))
			.exchange()
			.expectStatus().isOk()
			.expectBody()
			.json("[]");
	}

	@Test
	void testChallengeExpired() {
		Long expiredTimestamp = System.currentTimeMillis() - HALF_HOUR_MILLIS;
		webClient
			.get().uri(uriBuilder -> uriBuilder
				.path(CHALLENGE_URI)
				.queryParam("device_id", "test_device_id")
				.build()
			)
			.header(SIGNATURE_HEADER_NAME, String.format(SIGNATURE_HEADER_VALUE, expiredTimestamp))
			.exchange()
			.expectStatus().isForbidden()
			.expectBody()
			.jsonPath("$['error']").isEqualTo(ChallengeResource.CHALLENGE_REJECTED)
			.jsonPath("$['message']").hasJsonPath();
	}

	@Test
	void testNoCredentialsFound() {
		webClient
			.get().uri(uriBuilder -> uriBuilder
				.path(CHALLENGE_URI)
				.queryParam("device_id", "test_device_id")
				.build()
			)
			.header(SIGNATURE_HEADER_NAME, String.format(SIGNATURE_HEADER_VALUE, System.currentTimeMillis()))
			.exchange()
			.expectStatus().is5xxServerError()
			.expectBody()
			.jsonPath("$['error']").isEqualTo(ChallengeResource.INTERNAL_ERROR)
			.jsonPath("$['message']").hasJsonPath();
	}

}
