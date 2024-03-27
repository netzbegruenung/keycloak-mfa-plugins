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
@Sql(scripts = {"/import-test-data.sql"},
	config = @SqlConfig(transactionMode = ISOLATED)
)
@Sql(
	scripts = "/delete-test-data.sql",
	config = @SqlConfig(transactionMode = ISOLATED),
	executionPhase = AFTER_TEST_METHOD
)
public class ChallengeResourceTest {

	private final static String CHALLENGE_URI = "/realms/baeldung/challenges";

	private final static String SIGNATURE_HEADER_NAME = "Signature";

	private final static String VALID_SIGNATURE_HEADER_VALUE = "keyId:test_device_id,created:%d,signature:base64encodedSignature";

	private final static String INVALID_SIGNATURE_HEADER_VALUE = "keyId:not_existing,created:%d,signature:base64encodedSignature";

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
	void testInvalidSignature() {
		webClient
			.get().uri(uriBuilder -> uriBuilder
				.path(CHALLENGE_URI)
				.build()
			)
			.header(SIGNATURE_HEADER_NAME, String.format(VALID_SIGNATURE_HEADER_VALUE, System.currentTimeMillis()))
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
				.build()
			)
			.header(SIGNATURE_HEADER_NAME, String.format(INVALID_SIGNATURE_HEADER_VALUE, System.currentTimeMillis()))
			.exchange()
			.expectStatus().is4xxClientError()
			.expectBody()
			.jsonPath("$['error']").isEqualTo(ChallengeResource.NO_CREDENTIAL)
			.jsonPath("$['message']").hasJsonPath();
	}

}
