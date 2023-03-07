package netzbegruenung.keycloak.authenticator;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.common.Profile;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.jdbc.DataSourceBuilder;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.web.server.LocalServerPort;
import org.springframework.core.io.ClassPathResource;
import org.springframework.jdbc.datasource.init.ResourceDatabasePopulator;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import netzbegruenung.keycloak.dev.AuthorizationServerApp;

import javax.sql.DataSource;

import org.junit.jupiter.api.BeforeAll;

@ExtendWith(SpringExtension.class)
@SpringBootTest(classes = { AuthorizationServerApp.class }, webEnvironment = WebEnvironment.RANDOM_PORT)
@ActiveProfiles("test")
public class SmsAuthenticatorLiveTest {

	private static final Logger log = LoggerFactory.getLogger(SmsAuthenticatorLiveTest.class);

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

		Thread.sleep(60*60*1000);

	}

}
