package netzbegruenung.keycloak.authenticator;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.jdbc.DataSourceBuilder;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.boot.web.server.LocalServerPort;
import org.springframework.boot.web.server.WebServer;
import org.springframework.context.annotation.Bean;
import org.springframework.core.io.ClassPathResource;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.datasource.init.ResourceDatabasePopulator;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.web.client.RestTemplate;

import netzbegruenung.keycloak.dev.AuthorizationServerApp;

import static org.junit.jupiter.api.Assertions.*;

import javax.sql.DataSource;

import org.junit.jupiter.api.BeforeAll;

@ExtendWith(SpringExtension.class)
@SpringBootTest(classes = { AuthorizationServerApp.class }, webEnvironment = WebEnvironment.RANDOM_PORT)
@ActiveProfiles("test")
public class ContextIntegrationLiveTest {

	private static final Logger log = LoggerFactory.getLogger(ContextIntegrationLiveTest.class);

	@LocalServerPort
	int serverPort;


	@BeforeAll
	public static void populateTestDatabase() throws Exception {
		log.info("Populating database...");
		DataSource ds =  DataSourceBuilder.create()
			.driverClassName("org.h2.Driver")
			.url("jdbc:h2:./target/customuser")
			.username("SA")
			.password("")
			.build();

		ResourceDatabasePopulator populator = new ResourceDatabasePopulator(false, false, "UTF-8",
			new ClassPathResource("custom-database-data.sql"));
		populator.execute(ds);

	}

	@Test
	public void whenLoadApplication_thenSuccess() throws InterruptedException {
		log.info("Server port: {}", serverPort);

		String baseUrl = "http://localhost:" + serverPort;
//		ResponseEntity<String> response = restTemplate.getForEntity( baseUrl + "/auth" , String.class);
//		assertNotNull(response);
//		assertEquals(HttpStatus.OK, response.getStatusCode());

		log.info("Keycloak test server available at {}/auth", baseUrl);
		log.info("To test a custom provider user login, go to {}/auth/realms/baeldung/account",baseUrl);

		Thread.sleep(60*60*1000);

	}

}
