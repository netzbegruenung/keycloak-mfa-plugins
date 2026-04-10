package netzbegruenung.keycloak;

import dasniko.testcontainers.keycloak.KeycloakContainer;
import org.jboss.logging.Logger;
import org.jboss.shrinkwrap.resolver.api.maven.Maven;
import org.testcontainers.containers.Network;
import org.testcontainers.images.PullPolicy;
import org.testcontainers.utility.MountableFile;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

public class KeycloakTestContainer extends KeycloakContainer {

	private static final Logger log = Logger.getLogger(KeycloakTestContainer.class);

	public static final String KEYCLOAK_IMAGE =
		String.format("quay.io/keycloak/keycloak:%s", System.getProperty("keycloak.version", "26.5.4"));


	static final String[] deps = {
		"org.wildfly.client:wildfly-client-config",
		"org.jboss.resteasy:resteasy-client",
		"org.jboss.resteasy:resteasy-client-api",
		"org.keycloak:keycloak-admin-client",
		"com.googlecode.libphonenumber:libphonenumber"
	};

	static List<File> getDeps() {
		List<File> dependencies = new ArrayList<File>();
		for (String dep : deps) {
			dependencies.addAll(getDep(dep));
		}
		return dependencies;
	}

	static List<File> getDep(String pkg) {
		return Maven.resolver()
			.loadPomFromFile("./pom.xml")
			.resolve(pkg)
			.withoutTransitivity()
			.asList(File.class);
	}

	private KeycloakTestContainer() {
		super(KEYCLOAK_IMAGE);
		withImagePullPolicy(PullPolicy.alwaysPull());
		withReuse(true);
		withProviderClassesFrom("target/classes");
		withProviderLibsFrom(getDeps());
		withLogConsumer(new JbossLogConsumer(log).withPrefix("Keycloak"));
		withAccessToHost(true);
		if (isJacocoPresent()) {
			withCopyFileToContainer(
					MountableFile.forHostPath("target/jacoco-agent/"),
					"/jacoco-agent"
				)
				.withEnv("JAVA_OPTS", "-javaagent:/jacoco-agent/org.jacoco.agent-runtime.jar=destfile=/tmp/jacoco.exec");
		}
	}

	public KeycloakTestContainer(Network network) {
		this();
		withNetwork(network);
	}

	private static boolean isJacocoPresent() {
		return Files.exists(Path.of("target/jacoco-agent/org.jacoco.agent-runtime.jar"));
	}

	@Override
	public void stop() {
		try {
			String containerId = getContainerId();
			String containerShortId;
			if (containerId.length() > 12) {
				containerShortId = containerId.substring(0, 12);
			} else {
				containerShortId = containerId;
			}
			getDockerClient().stopContainerCmd(containerId).exec();
			if (isJacocoPresent()) {
				Files.createDirectories(Path.of("target", "jacoco-report"));
				copyFileFromContainer("/tmp/jacoco.exec", "./target/jacoco-report/jacoco-%s.exec".formatted(containerShortId));
			}
		} catch (IOException e) {
			throw new RuntimeException(e);
		} finally {
			super.stop();
		}
	}
}
