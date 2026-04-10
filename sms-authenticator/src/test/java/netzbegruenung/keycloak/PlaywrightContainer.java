package netzbegruenung.keycloak;

import org.jboss.logging.Logger;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.Network;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.utility.DockerImageName;

import java.util.Objects;

public class PlaywrightContainer extends GenericContainer<PlaywrightContainer> {

	private static final Logger log = Logger.getLogger(PlaywrightContainer.class);

	private static final String playwrightVersion = Objects.requireNonNull(System.getProperty("playwright.version"));

	public PlaywrightContainer(Network network) {
		super(DockerImageName.parse("mcr.microsoft.com/playwright").withTag("v%s".formatted(playwrightVersion)));
		withNetwork(network);
		withExposedPorts(3000);
		withCommand("/bin/sh", "-c", "npx -y playwright@%s run-server --port 3000 --host 0.0.0.0".formatted(playwrightVersion));
		waitingFor(Wait.forLogMessage(".*Listening on ws://0.0.0.0:3000.*", 1));
		withLogConsumer(new JbossLogConsumer(log).withPrefix("Playwright"));
	}
}
