package netzbegruenung.keycloak;

import org.jboss.logging.Logger;
import org.testcontainers.containers.output.OutputFrame;

import java.util.function.Consumer;

public class JbossLogConsumer implements Consumer<OutputFrame> {
	private final Logger log;
	private final String prefix;

	public JbossLogConsumer(Logger log) {
		this.log = log;
		this.prefix = "";
	}

	public JbossLogConsumer(Logger log, String prefix) {
		this.log = log;
		this.prefix = prefix;
	}



	@Override
	public void accept(OutputFrame frame) {
		final String message = "[%s] %s".formatted(prefix, frame.getUtf8String().trim());
		switch (frame.getType()) {
			case STDOUT -> log.info(message);
			case STDERR -> log.error(message);
			default -> log.info(message);
		}
	}

	public Consumer<OutputFrame> withPrefix(String prefix) {
		return new JbossLogConsumer(log, prefix);
	}
}
