package netzbegruenung.keycloak.app;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.common.Profile;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.web.server.LocalServerPort;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import netzbegruenung.keycloak.dev.AuthorizationServerApp;

import org.junit.jupiter.api.BeforeAll;

@ExtendWith(SpringExtension.class)
@SpringBootTest(classes = { AuthorizationServerApp.class }, webEnvironment = WebEnvironment.DEFINED_PORT)
@ActiveProfiles("test")
public class AppAuthenticatorLiveTest {

	private static final Logger log = LoggerFactory.getLogger(AppAuthenticatorLiveTest.class);

	@LocalServerPort
	int serverPort;


	@BeforeAll
	public static void initProfile() throws Exception {
		Profile profile = Profile.configure();
		Profile.init(profile.getName(), profile.getFeatures());
	}

	@Test
	public void whenLoadApplication_thenSuccess() throws InterruptedException {
		log.info("Server port: {}", serverPort);

		String baseUrl = "http://localhost:" + serverPort;

		log.info("Keycloak test server available at {}/auth", baseUrl);
		log.info("To test a custom provider user login, go to {}/auth/realms/baeldung/account",baseUrl);

		Thread.sleep(3*60*60*1000);

	}

}
